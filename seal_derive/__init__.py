"""seal_derive: 口令派生与版本化封存."""

__version__ = "0.1.0"

#: The technical domain this package belongs to.
DOMAIN = "key-management"

#: Category headings in corpus.md whose tags this domain claims.
SOURCE_CATEGORIES = ("🔐 加密 / 密钥管理", "🧬 隐私计算 / 差分隐私")

from .core import KeyRing  # noqa: E402  (re-exported after the constants above)

__all__ = ["KeyRing", "DOMAIN", "SOURCE_CATEGORIES", "__version__"]
