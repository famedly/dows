# SPDX-FileCopyrightText: 2026 Famedly GmbH (info@famedly.com)
#
# SPDX-License-Identifier: AGPL-3.0-or-later

{ inputs, ... }:
{
  perSystem =
    { config, pkgs, ... }:
    let
      mkDows =
        rustPlatform:
        rustPlatform.buildRustPackage {
          pname = "dows";
          version = (pkgs.lib.importTOML ../Cargo.toml).package.version;

          src = pkgs.lib.fileset.toSource {
            root = ../.;
            fileset = pkgs.lib.fileset.unions [
              ../Cargo.toml
              ../Cargo.lock
              ../build.rs
              ../src
            ];
          };

          cargoLock.lockFile = ../Cargo.lock;

          env.GIT_COMMIT_HASH = inputs.self.rev or inputs.self.dirtyRev or "unknown";

          meta = {
            description = "DNS over WebSocket proxy";
            mainProgram = "dows";
          };
        };
    in
    {
      packages = {
        dows = mkDows pkgs.pkgsStatic.rustPlatform;
        default = config.packages.dows;

        docker-image = pkgs.dockerTools.buildLayeredImage {
          name = "dows";
          tag = "latest";

          config = {
            Entrypoint = [ (pkgs.lib.getExe config.packages.dows) ];
            ExposedPorts."8080/tcp" = { };
          };
        };
      };
    };
}
