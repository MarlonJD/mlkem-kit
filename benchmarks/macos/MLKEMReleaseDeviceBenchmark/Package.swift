// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "MLKEMReleaseDeviceBenchmark",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "MLKEMReleaseDeviceBenchmark",
            targets: ["MLKEMReleaseDeviceBenchmark"]
        )
    ],
    dependencies: [
        .package(path: "../../../platforms/swift")
    ],
    targets: [
        .executableTarget(
            name: "MLKEMReleaseDeviceBenchmark",
            dependencies: [
                .product(name: "MLKEMNativeSwift", package: "swift")
            ]
        )
    ]
)
