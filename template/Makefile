ARCHS = arm64 arm64e
TARGET = iphone:clang:latest:14.0
INSTALL_TARGET_PROCESSES = ShadowTrackerExtra

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = HamadShield
HamadShield_FILES = Tweak.xm
HamadShield_CFLAGS = -fobjc-arc

include $(THEOS_MAKE_PATH)/tweak.mk
