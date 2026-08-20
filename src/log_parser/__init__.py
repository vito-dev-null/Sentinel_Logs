"""log_parser package."""

from .cli import main
from .metrics import MetricsRegistry
from .multi_source import InMemoryQueueBackend, MultiSourceTailer, QueueBackend
from .parsers import AppLogParser, BaseLogParser, ParserRegistry, SyslogParser
from .schema import LogRecord
from .secrets import AWSSecretsManagerProvider, EnvSecretProvider, SecretProvider, VaultSecretProvider
from .sinks import AlertEngine, AlertRule, BaseSink, FileSink, StdoutSink, SyslogSink, WebhookSink, create_sink
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
    "StdoutSink",
    "SyslogSink",
    "SyslogParser",
    "VaultSecretProvider",
    "WebhookSink",
    "create_sink",
    "main",
]

__version__ = "0.2.0"
