const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize_option = b.option(
        std.builtin.OptimizeMode,
        "optimize",
        "Optimization mode: Debug, ReleaseSafe, ReleaseFast, ReleaseSmall",
    ) orelse .Debug;

    const exe = b.addExecutable(.{
        .name = "server",
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize_option,
    });

    exe.linkLibC();
    exe.linkSystemLibrary("ssl");
    exe.linkSystemLibrary("crypto");
    exe.linkSystemLibrary("z");

    b.installArtifact(exe);

    const install_config = b.addInstallFile(
        b.path("config.json"),
        "bin/config.json",
    );
    const install_proxies = b.addInstallFile(
        b.path("proxies.json"),
        "bin/proxies.json",
    );
    b.getInstallStep().dependOn(&install_config.step);
    b.getInstallStep().dependOn(&install_proxies.step);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    const run_step = b.step("run", "Run the cloud browser server");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{
        .root_source_file = b.path("server.zig"),
        .target = target,
        .optimize = optimize_option,
    });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_unit_tests.step);
}
