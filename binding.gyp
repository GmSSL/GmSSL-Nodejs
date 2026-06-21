{
  "targets": [
    {
      "target_name": "gmssl_native",
      "sources": ["src/gmssl.cc"],
      "include_dirs": [
        "<!@(node -p \"require('node-addon-api').include\")",
        "<!(node -p \"(process.env.GMSSL_ROOT || '/usr/local') + '/include'\")"
      ],
      "libraries": [
        "<!(node -p \"'-L' + (process.env.GMSSL_ROOT || '/usr/local') + '/lib'\")",
        "-lgmssl"
      ],
      "cflags!": ["-fno-exceptions"],
      "cflags_cc!": ["-fno-exceptions"],
      "cflags_cc": ["-std=c++17"],
      "defines": ["NAPI_DISABLE_CPP_EXCEPTIONS"],
      "conditions": [
        ["OS=='mac'", {
          "xcode_settings": {
            "GCC_ENABLE_CPP_EXCEPTIONS": "YES",
            "CLANG_CXX_LIBRARY": "libc++",
            "MACOSX_DEPLOYMENT_TARGET": "10.15",
            "OTHER_CFLAGS": ["-std=c++17"],
            "OTHER_LDFLAGS": [
              "<!(node -p \"'-L' + (process.env.GMSSL_ROOT || '/usr/local') + '/lib'\")",
              "-lgmssl",
              "<!(node -p \"'-Wl,-rpath,' + (process.env.GMSSL_ROOT || '/usr/local') + '/lib'\")"
            ]
          },
          "libraries": []
        }],
        ["OS=='linux'", {
          "cflags_cc": ["-std=c++17"],
          "ldflags": [
            "<!(node -p \"'-Wl,-rpath,' + (process.env.GMSSL_ROOT || '/usr/local') + '/lib'\")"
          ]
        }]
      ]
    }
  ]
}
