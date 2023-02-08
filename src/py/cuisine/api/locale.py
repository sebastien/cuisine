# =============================================================================
#
# LOCALE
#
# =============================================================================


def locale_check(locale):
    locale_data = sudo("locale -a | egrep '^%s$' ; true" % (locale,))
    return locale_data == locale


def locale_ensure(locale):
    if not locale_check(locale):
        with fabric.context_managers.settings(warn_only=True):
            sudo("/usr/share/locales/install-language-pack %s" % (locale,))
        sudo("dpkg-reconfigure locales")


