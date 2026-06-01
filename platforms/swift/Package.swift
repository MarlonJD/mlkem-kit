// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "MLKEMNativeSwift",
    platforms: [
        .iOS(.v13),
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "MLKEMNativeSwift",
            targets: ["MLKEMNativeSwift"]
        )
    ],
    targets: [
        .target(
            name: "MLKEMNativeSwift"
        ),
        .testTarget(
            name: "MLKEMNativeSwiftTests",
            dependencies: ["MLKEMNativeSwift"]
        )
    ]
)
