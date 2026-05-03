# Generate PAM test data files substituting @ROOTUID@, @ROOTGID@, @PAMWRAPDIR@
# pam_conf is defined by the parent (tests/meson.build) before calling subdir()

configure_file(
    input: 'nss-passwd.in',
    output: 'nss-passwd',
    configuration: pam_conf,
    install: false,
)

configure_file(
    input: 'nss-group.in',
    output: 'nss-group',
    configuration: pam_conf,
    install: false,
)

configure_file(
    input: 'ocserv.in',
    output: 'ocserv',
    configuration: pam_conf,
    install: false,
)
