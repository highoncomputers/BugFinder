from __future__ import annotations

import typer
from rich import print as rprint

from bugfinder import __version__

app = typer.Typer(
    name="bugfinder",
    help="BugFinder - AI-powered autonomous bug bounty assistant",
    no_args_is_help=False,
    rich_markup_mode="rich",
)


def _version_callback(value: bool) -> None:
    if value:
        rprint(f"BugFinder v{__version__}")
        raise typer.Exit()


@app.callback(invoke_without_command=True)
def main(
    ctx: typer.Context,
    version: bool = typer.Option(False, "--version", "-V", callback=_version_callback, is_eager=True),
) -> None:
    if ctx.invoked_subcommand is None:
        launch_tui()


@app.command()
def proxy(
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Host to bind to"),
    port: int = typer.Option(8081, "--port", "-p", help="Port to bind to"),
    web_port: int = typer.Option(8080, "--web-port", "-w", help="Web UI port"),
) -> None:
    """Launch the intercepting proxy server."""
    import asyncio

    from bugfinder.proxy.server import ProxyServer

    async def _run():
        rprint(f"[green]Starting BugFinder Proxy on {host}:{port}[/green]")
        rprint("[yellow]Configure your browser to use this proxy[/yellow]")
        rprint(f"[yellow]View captured traffic at http://127.0.0.1:{web_port}/proxy[/yellow]")
        server = ProxyServer(host=host, port=port)
        await server.start()
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            await server.stop()

    asyncio.run(_run())


@app.command()
def web(
    host: str = typer.Option("127.0.0.1", "--host", "-H", help="Host to bind to"),
    port: int = typer.Option(8080, "--port", "-p", help="Port to bind to"),
) -> None:
    """Launch the BugFinder Web UI."""
    import uvicorn

    rprint(f"[green]Starting BugFinder Web UI on http://{host}:{port}[/green]")
    uvicorn.run("bugfinder.web.app:app", host=host, port=port, log_level="info")


def launch_tui() -> None:
    from bugfinder.cli.app import BugFinderTUI

    tui = BugFinderTUI()
    tui.run()


if __name__ == "__main__":
    app()
