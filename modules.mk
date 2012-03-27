mod_wurfl.la: mod_wurfl.slo
	$(SH_LINK) -rpath $(libexecdir) -module -avoid-version  mod_wurfl.lo
DISTCLEAN_TARGETS = modules.mk
shared =  mod_wurfl.la
