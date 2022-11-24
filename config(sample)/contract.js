const fs = require('fs');//sample
const BASE_ADDRESS_URL = 'CONTRACT_ADDRESS';
const BASE_ABI_URL = 'CONTRACT_ABI';
const DIDLedger_JSON =require('DIDLedger_DEPLOYEE_JSON');


module.exports = {
    DEPLOYED_JSON_DIDLedger: DIDLedger_JSON,
    DEPLOYED_ADDRESS_DIDLedger: fs.readFileSync(`${BASE_ADDRESS_URL}deployedAddressDIDLedger`, 'utf8').replace(/\n|\r/g, ""),
    DEPLOYED_ABI_DIDLedger: JSON.parse(fs.existsSync(`${BASE_ABI_URL}deployedABIDIDLedger`) && fs.readFileSync(`${BASE_ABI_URL}deployedABIDIDLedger`, 'utf8')),

}