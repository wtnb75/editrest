import click
import io
import editor
import requests
import json
import yaml
import toml
import pprint
import ast
import functools
import jsonpatch
from logging import getLogger
from typing import Optional
from .version import VERSION

_log = getLogger(__name__)


class NotChanged(Exception):
    pass


@click.version_option(version=VERSION, prog_name="editrest")
@click.group(invoke_without_command=True)
@click.pass_context
def cli(ctx):
    """REST read-modify-write"""
    if ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


def parse(b: bytes, format: str = "json"):
    if format == "json":
        return json.loads(b)
    elif format == "yaml":
        return yaml.safe_load(io.BytesIO(b))
    elif format == "toml":
        return toml.loads(b.decode())
    elif format == "pprint":
        return ast.literal_eval(b.decode())
    raise NotImplementedError(f"invalid format {format}")


def encode(d, format: str = "json") -> bytes:
    if format == "json":
        return json.dumps(d, ensure_ascii=False, sort_keys=True, indent=2)
    elif format == "yaml":
        out = io.BytesIO()
        yaml.safe_dump(d, out, default_flow_style=False, encoding="utf-8")
        return out.getvalue()
    elif format == "toml":
        return toml.dumps(d).encode()
    elif format == "pprint":
        return pprint.pformat(d)
    raise NotImplementedError(f"invalid format {format}")


def do1(url: str, read_method: str = "GET", write_method: str = "PUT",
        format: str = "json", session: Optional[requests.Session] = None,
        dry: bool = False) -> requests.Response:
    if session is None:
        session = requests.Session()
    old_res = session.request(read_method, url)
    _log.debug("response %s, headers=%s", old_res, str(old_res.headers))
    old_res.raise_for_status()
    data = old_res.json()
    new_msg = editor.edit(contents=encode(data, format), suffix=f".{format}")
    new_data = parse(new_msg, format)
    if data == new_data:
        raise NotChanged("data not changed")
    p = jsonpatch.make_patch(data, new_data)
    click.echo(f"change: {p.patch}")
    if not dry:
        click.confirm('Do you want to continue?', abort=True)
        res = session.request(write_method, url, json=new_data)
        _log.debug("response %s, headers=%s", res, str(res.headers))
        try:
            out = res.json()
            click.echo(
                f"{write_method} {url} {new_data} -> {res.status_code} {out}")
        except Exception:
            click.echo(
                f"{write_method} {url} {new_data} -> {res.status_code} {res.content}")
        res.raise_for_status()
        return res
    click.echo(f"(dry) {write_method} {encode(new_data, 'json')}")
    return None


def base_options(func):
    @click.option("--format", default="json", type=click.Choice(["json", "yaml", "toml", "pprint"]), show_default=True)
    @click.option("--dry/--no-dry", default=False, show_default=True)
    @click.option("--user", "-u", help="user:password")
    @click.option("--bearer", help="bearer token")
    @click.option("--insecure/--verify", "-k", default=False, show_default=True)
    @click.option("--content-type", default="application/json", show_default=True)
    @click.option("--accept", default="application/json", show_default=True)
    @click.option("--headers", "-H", multiple=True, help="'Header: value'")
    @click.option("--params", multiple=True, help="param=value")
    @click.option("--verbose/--quiet")
    @click.option("--proxy", "-x", help="http/https proxy")
    @click.option("--cacert", type=click.Path(exists=True, file_okay=True, dir_okay=False),
                  help="CA root certificate")
    @click.option("--cert", type=click.Path(exists=True, file_okay=True, dir_okay=False),
                  help="mTLS client side certificate")
    @click.option("--resolve", multiple=True, help="hostname:port:ipaddress")
    @click.option("--location", "-L", type=bool)
    @click.argument("url")
    @functools.wraps(func)
    def _(url, format, dry, user, bearer, insecure, content_type, accept,
          headers, verbose, params, proxy, cacert, cert, resolve, location,
          *args, **kwargs):
        import logging
        fmt = "%(asctime)s %(levelname)s %(name)s %(message)s"
        if verbose is None:
            logging.basicConfig(format=fmt, level="INFO")
        elif verbose:
            logging.basicConfig(format=fmt, level="DEBUG")
        else:
            logging.basicConfig(format=fmt, level="WARNING")
        session = requests.Session()
        session.verify = not insecure
        if not location:
            session.max_redirects = 0
        if cacert:
            session.verify = cacert
        session.headers["content-type"] = content_type
        session.headers["accept"] = accept
        for h in headers:
            k, v = h.split(":", 1)
            session.headers[k] = v.strip()
        if user:
            session.auth = user.split(":", 1)
        if bearer:
            session.headers["Authorization"] = f"Bearer {bearer}"
        if proxy:
            session.proxies.update({"http": proxy, "https": proxy})
        if cert:
            session.cert = cert
        for p in params:
            k, v = p.split("=", 1)
            session.params[k] = v
        if resolve:
            resolve_map = {}
            for resolve1 in resolve:
                ll = resolve1.split(":", 2)
                if len(ll) == 3:
                    k = (ll[0], int(ll[1]))
                    v = ll[2]
                elif len(ll) == 2:
                    k = ll[0]
                    v = ll[1]
                else:
                    raise Exception(r"invalid resolve option: {l}")
                resolve_map[k] = v
            # https://stackoverflow.com/questions/22609385/python-requests-library-define-specific-dns
            from urllib3.util import connection
            _orig_create_connection = connection.create_connection

            def patched_create_connection(address, *args, **kwargs):
                host, port = address
                if (host, port) in resolve_map:
                    hostname = resolve_map.get((host, port))
                    _log.debug("hostport resolve %s -> %s", address, hostname)
                elif host in resolve_map:
                    hostname = resolve_map.get(host)
                    _log.debug("host resolve %s -> %s", address, hostname)
                else:
                    hostname = host
                    _log.debug("raw resolve %s -> %s", address, hostname)
                return _orig_create_connection((hostname, port), *args, **kwargs)
            connection.create_connection = patched_create_connection
        return func(url=url, format=format, dry=dry, session=session, *args, **kwargs)
    return _


@cli.command()
@base_options
def get_put(url, format, dry, session):
    """GET url and PUT"""
    do1(url=url, read_method="GET", write_method="PUT",
        format=format, dry=dry, session=session)


@cli.command()
@base_options
def get_delete(url, format, dry, session):
    """GET url and DELETE"""
    do1(url=url, read_method="GET", write_method="DELETE",
        format=format, dry=dry, session=session)


@cli.command()
@base_options
def get_post(url, format, dry, session):
    """GET url and POST"""
    do1(url=url, read_method="GET", write_method="POST",
        format=format, dry=dry, session=session)


@cli.command()
@base_options
def get_patch(url, format, dry, session):
    """GET url and PATCH"""
    do1(url=url, read_method="GET", write_method="PATCH",
        format=format, dry=dry, session=session)


@cli.command()
@base_options
@click.option("--read-method", default="GET", show_default=True)
@click.option("--write-method", default="PUT", show_default=True)
def run(url, format, dry, session, read_method, write_method):
    """{read-method} url and {write-method}"""
    do1(url=url, read_method=read_method, write_method=write_method,
        format=format, dry=dry, session=session)


if __name__ == "__main__":
    cli()
