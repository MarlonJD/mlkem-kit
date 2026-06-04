// swift-tools-version: 5.9

import PackageDescription

let package = Package(
    name: "MLKEMTimingSanityBenchmark",
    platforms: [
        .macOS(.v13)
    ],
    products: [
        .executable(
            name: "MLKEMTimingSanityBenchmark",
            targets: ["MLKEMTimingSanityBenchmark"]
        )
    ],
    dependencies: [
        .package(path: "../../../platforms/swift")
    ],
    targets: [
        .executableTarget(
            name: "MLKEMTimingSanityBenchmark",
            dependencies: [
                .product(name: "MLKEMNativeSwift", package: "swift")
            ]
        )
    ]
)
