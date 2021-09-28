project('shstash', 'c',
        default_options : ['c_std=c17'])
libsds = static_library('sds', 'thirdparty/sds/sds.c')
executable('shstash', ['main.c'], link_with : libsds)
