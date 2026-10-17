"""Argument errors never echo mistakenly supplied secret values."""
import argparse


class SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message):
        self.exit(2, '{"ok": false, "error": "E_ARGUMENT"}\n')
