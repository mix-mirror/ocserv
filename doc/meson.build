ronn = find_program('ronn', required: false)
sh   = find_program('sh')

if ronn.found()
  # ocserv.8.md embeds sample.config in place of the @CONFIGFILE@ placeholder
  # before being handed to ronn.
  ocserv_md = custom_target('ocserv.8.md-with-config',
    input:   ['gen-ocserv8-md.sh', 'ocserv.8.md', 'sample.config'],
    output:  'ocserv.8.md',
    command: [sh, '@INPUT0@', '@INPUT1@', '@INPUT2@', '@OUTPUT@'],
  )
  ocserv8_manpage = custom_target('ocserv.8',
    input:       ocserv_md,
    output:      'ocserv.8',
    command:     [ronn, '--roff', '@INPUT@', '-o', '@OUTDIR@'],
    install:     true,
    install_dir: get_option('mandir') / 'man8',
  )
elif fs.exists('ocserv.8')
  install_data('ocserv.8',
    install_dir: get_option('mandir') / 'man8',
  )
endif

foreach page : ['occtl.8', 'ocpasswd.8']
  if ronn.found()
    custom_target(page,
      input:       page + '.md',
      output:      page,
      command:     [ronn, '--roff', '@INPUT@', '-o', '@OUTDIR@'],
      install:     true,
      install_dir: get_option('mandir') / 'man8',
    )
  elif fs.exists(page)
    install_data(page,
      install_dir: get_option('mandir') / 'man8',
    )
  endif
endforeach
