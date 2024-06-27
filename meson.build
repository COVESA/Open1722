project(
    'Open1722',
    'c',
    version: '0.1.0',
    license: 'BSD-3-Clause',
    meson_version: '>=0.56.0',
)

avtp_lib = library(
    'open1722',
    [
     'src/avtp.c',
     'src/avtp_ieciidc.c',
     'src/avtp_stream.c',

     'src/avtp/Utils.c',
     'src/avtp/acf/Ntscf.c',
     'src/avtp/acf/Tscf.c',
     'src/avtp/CommonHeader.c',
     'src/avtp/acf/Common.c',
     'src/avtp/acf/Can.c',
     'src/avtp/acf/CanBrief.c',
     'src/avtp/acf/Sensor.c',
     'src/avtp/acf/SensorBrief.c',
     'src/avtp/aaf/PcmStream.c',
     'src/avtp/aaf/CommonStream.c',
     'src/avtp/Udp.c',
     'src/avtp/Rvf.c',
     'src/avtp/Crf.c',
     'src/avtp/cvf/Cvf.c',
     'src/avtp/cvf/H264.c',
     'src/avtp/cvf/Jpeg2000.c',
     'src/avtp/cvf/Mjpeg.c',
    ],
    version: meson.project_version(),
    include_directories: include_directories('include'),
    install: true,
)

avtp_dep = declare_dependency(
    link_with: avtp_lib,
    include_directories: include_directories('include'),
)

install_headers(
    'include/avtp/Byteorder.h',
    'include/avtp/Defines.h',
    'include/avtp/CommonHeader.h',
    'include/avtp/Udp.h',
    'include/avtp/Utils.h',
    'include/avtp/Rvf.h',
    'include/avtp/Crf.h',
    subdir : 'avtp'
)

install_headers(
    'include/avtp/acf/CanBrief.h',
    'include/avtp/acf/Can.h',
    'include/avtp/acf/Common.h',
    'include/avtp/acf/Ntscf.h',
    'include/avtp/acf/SensorBrief.h',
    'include/avtp/acf/Sensor.h',
    'include/avtp/acf/Tscf.h',
    subdir : 'avtp/acf'
)

install_headers(
    'include/avtp/aaf/PcmStream.h',
    'include/avtp/aaf/CommonStream.h',
    subdir : 'avtp/aaf'
)

install_headers(
    'src/avtp/cvf/Cvf.c',
    'src/avtp/cvf/H264.c',
    'src/avtp/cvf/Jpeg2000.c',
    'src/avtp/cvf/Mjpeg.c',
    subdir : 'avtp/cvf'
)

pkg = import('pkgconfig')
pkg.generate(avtp_lib,
    description: 'AVTP packetization library',
    url: 'github.com/COVESA/Open1722',
)

if get_option('tests') == 'disabled'
    cmocka = disabler()
else
    cmocka = dependency('cmocka', required: get_option('tests') == 'enabled')
endif

if cmocka.found()
    test_avtp = executable(
        'test-avtp',
        'unit/test-avtp.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test_can = executable(
        'test-can',
        'unit/test-can.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        link_args : '-lm', 
        dependencies: cmocka,
        build_by_default: false,
    )

    test_aaf = executable(
        'test-aaf',
        'unit/test-aaf.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test_crf = executable(
        'test-crf',
        'unit/test-crf.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test_stream = executable(
        'test-stream',
        'unit/test-stream.c',
        'src/avtp_stream.c',
        include_directories: include_directories('include', 'src'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test_cvf = executable(
        'test-cvf',
        'unit/test-cvf.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test_rvf = executable(
        'test-rvf',
        'unit/test-rvf.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test_ieciidc = executable(
        'test-ieciidc',
        'unit/test-ieciidc.c',
        include_directories: include_directories('include'),
        link_with: avtp_lib,
        dependencies: cmocka,
        build_by_default: false,
    )

    test('AVTP API', test_avtp)
    test('Stream API', test_stream)
    test('AAF API', test_aaf)
    test('CRF API', test_crf)
    test('CVF API', test_cvf)
    test('RVF API', test_rvf)
    test('IEC61883/IIDC API', test_ieciidc)
    test('ACF CAN API', test_can)
endif

subdir('examples')