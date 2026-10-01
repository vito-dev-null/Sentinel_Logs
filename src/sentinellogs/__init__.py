"""SentinelLogs: real-time log parsing, JSONL sinks, alerting, and metrics."""

from .cli import main
from .metrics import MetricsRegistry
from .multi_source import InMemoryQueueBackend, MultiSourceTailer, QueueBackend
from .parsers import AppLogParser, BaseLogParser, ParserRegistry, SyslogParser
from .schema import LogRecord
from .secrets import AWSSecretsManagerProvider, EnvSecretProvider, SecretProvider, VaultSecretProvider
from .sinks import (
    AlertEngine,
    AlertRule,
    BaseSink,
    FileSink,
    SentinelLogsSink,
    StdoutSink,
    SyslogSink,
    WebhookSink,
    create_sink,
)
from .tailer import LogTailer

__all__ = [
    "AlertEngine",
    "AlertRule",
    "AppLogParser",
    "AWSSecretsManagerProvider",
    "BaseLogParser",
    "BaseSink",
    "EnvSecretProvider",
    "FileSink",
    "InMemoryQueueBackend",
    "LogRecord",
    "LogTailer",
    "MetricsRegistry",
    "MultiSourceTailer",
    "ParserRegistry",
    "QueueBackend",
    "SecretProvider",
    "SentinelLogsSink",
    "StdoutSink",
    "SyslogSink",
    "SyslogParser",
    "VaultSecretProvider",
    "WebhookSink",
    "create_sink",
    "main",
]

__version__ = "0.2.0"
