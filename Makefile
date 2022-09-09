#
# This is a project Makefile. It is assumed the directory this Makefile resides in is a
# project subdirectory.
#

PROJECT_NAME := espnow_example
CPPFLAGS := -D MDF_VER=\"v1.0-156-gcf50274\"

include $(IDF_PATH)/make/project.mk

