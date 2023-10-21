from abc import ABCMeta, abstractmethod


class IEXICodec(metaclass=ABCMeta):             # Базовый абстрактный класс EXI кодека
    @abstractmethod
    def encode(self, message: str, namespace: str) -> bytes:
        """
        Кодирование сообщения в EXI, для кодирования используется схема (пространство имен)
        """
        raise NotImplementedError

    @abstractmethod
    def decode(self, stream: bytes, namespace: str) -> str:
        """
        Декодирование сообщения из EXI, для декодирования используется схема (пространство имен)
        """
        raise NotImplementedError

    @abstractmethod
    def get_version(self) -> str:
        pass
