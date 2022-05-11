require("@nomiclabs/hardhat-ethers")
require("./tasks/deploy.js")
require("dotenv").config()

/**
 * @type import('hardhat/config').HardhatUserConfig
 */
module.exports = {
  solidity: "0.8.13",
  paths: {
    sources: "./src/flat"
  },
  // networks: {
  //   arbitrumTestnet: {
  //     url: "https://rinkeby.arbitrum.io/rpc",
  //     accounts: [process.env.PRIVATE_KEY ?? ]
  //   },
  //   rinkeby: {
  //     url: "https://rinkeby.infura.io/v3/0e7fcc143f894d179aa51dbdc44d8ac5",
  //     accounts: [process.env.PRIVATE_KEY]
  //   }
  // }
};
