idf_component_register(
    SRCS "main.c"
        "ieee802154.c"
        "esp_esl.c"
        "bitmap.c"
    INCLUDE_DIRS "."
                 "include"
    EMBED_FILES "default_image.bmp"
)
