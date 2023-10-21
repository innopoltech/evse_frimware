from pydantic import BaseModel as PydanticBaseModel


class BaseModel(PydanticBaseModel):
    class Config:
        """
        Изменение стандартной конфигурации pydantic в соответствии с требованиями DIN SPEC 70121 и ISO 15118
        """

        # Разрешение ввода alias или имени поля 
        populate_by_name = True

        # Запрет дополнительных атрибутов при инициализации
        extra = "forbid"

        # Проверка установленных полей в экземпляре
        validate_assignment = True
