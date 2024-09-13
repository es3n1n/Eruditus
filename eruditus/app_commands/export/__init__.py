import asyncio
import logging
import subprocess
import tempfile

import discord
from discord import app_commands

_log = logging.getLogger("discord.eruditus.cmds.export")


class Export(app_commands.Group):
    def __init__(self) -> None:
        self._chat_export_tasks = []
        super().__init__(name="export")

    @app_commands.checks.bot_has_permissions(manage_channels=True, manage_roles=True)
    @app_commands.checks.has_permissions(manage_channels=True, manage_roles=True)
    @app_commands.command()
    async def chat(self, interaction: discord.Interaction) -> None:
        """Export CTF chat logs to a static site.

        Args:
            interaction: The interaction that triggered this command.
        """

        async def _handle_process(process: asyncio.subprocess.Process):
            _, _ = await process.communicate()
            channel, _, _ = self._chat_export_tasks.pop(0)
            message = (
                "Chat export task finished successfully, "
                f"{len(self._chat_export_tasks)} items remaining in the queue."
            )
            try:
                await channel.send(content=message)
            except discord.errors.HTTPException as err:
                _log.error("Failed to send message: %s", err)

            _log.info(message)
            if len(self._chat_export_tasks) == 0:
                return

            _, tmp, output_dirname = self._chat_export_tasks[0]
            asyncio.create_task(
                _handle_process(
                    await asyncio.create_subprocess_exec(
                        "chat_exporter",
                        tmp,
                        output_dirname,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                )
            )

        await interaction.response.defer()

        guild_category = interaction.channel.category
        exportable = set()
        for channel in guild_category.text_channels:
            exportable.add(channel.id)

            for thread in channel.threads:
                exportable.add(thread.id)

            for private in (True, False):
                async for thread in channel.archived_threads(
                    private=private, limit=None
                ):
                    exportable.add(thread.id)

        tmp = tempfile.mktemp()
        output_dirname = (
            f"[{guild_category.id}] {guild_category.name.replace('/', '_')}"
        )
        with open(tmp, "w", encoding="utf-8") as f:
            f.write("\n".join(map(str, exportable)))

        self._chat_export_tasks.append((interaction.channel, tmp, output_dirname))
        if len(self._chat_export_tasks) == 1:
            asyncio.create_task(
                _handle_process(
                    await asyncio.create_subprocess_exec(
                        "chat_exporter",
                        tmp,
                        output_dirname,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                    )
                )
            )

        await interaction.followup.send(
            "Export task started, chat logs will be available shortly.", silent=True
        )
