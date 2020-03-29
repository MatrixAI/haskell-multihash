{ pkgs ? import ./pkgs.nix }:

with pkgs;
let
  haskellPackages = haskell.packages.ghc865;
  strict = drv: haskell.lib.buildStrictly drv;
  drv = (haskellPackages.callPackage ./default.nix {}).overrideAttrs (attrs: {
    src = nix-gitignore.gitignoreSource [] ./.;
  });
in
  rec {
    library = drv;
    libraryStrict = strict drv;
    application = drv;
    applicationStrict = strict drv;
    docker = dockerTools.buildImage {
      name = applicationStrict.name;
      contents = applicationStrict;
      config = {
        Cmd = [ "/bin/multihash-exe" ];
      };
    };
  }
