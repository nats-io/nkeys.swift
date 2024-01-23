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
            targets: ["NKeys"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/Jarema/Base32",
            branch: "main"
        )
    ],
    targets: [
        // Targets are the basic building blocks of a package, defining a module or a test suite.
        // Targets can depend on other targets in this package and products from dependencies.
        .target(
            name: "NKeys",
            dependencies: [
                .product(name: "Base32", package: "Base32")
            ]
        ),

        .testTarget(
            name: "NKeys.Tests",
            dependencies: ["NKeys"]),
    ]
)
