include $(TOPDIR)/rules.mk

PKG_NAME:=nfqws2
PKG_RELEASE:=1

LUA_JIT?=1

ifeq ($(LUA_JIT),1)
 LUAJIT_VER?=2.1
 LUA_VER?=5.1
 LUA_DEP:=luajit
 #LUA_DEP:=luajit2
 LUA_INCLUDE:=-I$(STAGING_DIR)/usr/include/luajit-$(LUAJIT_VER)
 LUA_LIBRARY:=-L$(STAGING_DIR)/usr/lib -lluajit-$(LUA_VER)
else
 LUA_VER?=5.3
 LUA_DEP:=lua$(LUA_VER)
 LUA_INCLUDE:=-I$(STAGING_DIR)/usr/include/lua$(LUA_VER)
 LUA_LIBRARY:=-L$(STAGING_DIR)/usr/lib -llua$(LUA_VER)
endif

include $(INCLUDE_DIR)/package.mk

define Package/nfqws2
	SECTION:=net
	CATEGORY:=Network
	TITLE:=nfqws2
	SUBMENU:=Zapret
	DEPENDS:=+libnetfilter-queue +libmnl +libcap +zlib +$(LUA_DEP)
endef

define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	$(CP) ./nfq2/* $(PKG_BUILD_DIR)/
endef

define Build/Compile
	$(MAKE) -C $(PKG_BUILD_DIR) $(TARGET_CONFIGURE_OPTS) LUA_CFLAGS="$(LUA_INCLUDE)" LUA_LIB="$(LUA_LIBRARY)" 
endef

define Package/nfqws2/install
	$(INSTALL_DIR) $(1)/opt/zapret2/binaries/my
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/nfqws2 $(1)/opt/zapret2/binaries/my
endef

$(eval $(call BuildPackage,nfqws2))
