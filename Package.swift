// swift-tools-version: 5.6
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "NKeys",
    platforms: [
        .watchOS(.v6),
        .macOS(.v10_15)
    ],

    products: [
        // Products define the executables and libraries a package produces, making them visible to other packages.
        .library(
            name: "NKeys",
            targets: ["NKeys"])
    ],
    dependencies: [
        .package(url: "https://github.com/Jarema/Base32", from: "0.10.2"),
        .package(url: "https://github.com/jedisct1/swift-sodium.git", from: "0.9.0"),
        .package(url: "https://github.com/apple/swift-format.git", from: "0.509.0")
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NKeys",
            dependencies: [
                .product(name: "Base32", package: "Base32"),
                .product(name: "Sodium", package: "swift-sodium")
            ]
        ),

        .testTarget(
            name: "NKeys.Tests",
            dependencies: ["NKeys"])
    ]
)
