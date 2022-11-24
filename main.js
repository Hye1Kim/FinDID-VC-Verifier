const express = require('express');
const fileUpload = require('express-fileupload');
const app = express();
const PORT = 8000;
const bodyParser = require('body-parser');
const cors = require('cors');
const finDID= require('fin-did-auth');/*@dev*/
const jwt = require('access-jwt'); /*@dev*/
const DID_INFO = require('./config/did.js');
const ACCESS = require('./config/access.js');
const ACCOUNT = require('./config/account.js');
const axios = require('axios');
const keccak256 = require('keccak256')

app.use(express.static('upload'));
app.use(cors());
app.use(bodyParser.json()); 
app.use(bodyParser.urlencoded({ extended: true })); //원래 TRUE였습니다.


async function _createHash(data){

    const hash = keccak256(Buffer.from(JSON.stringify(data))).toString('hex')
    console.log(JSON.stringify(data));
    return hash
  
  }



// default options
app.use(fileUpload());

app.get('/ping', function(req, res) {
  res.send('pong');
});

app.accessKeyDB = new Map();

app.post('/accessToken', async function(req, res) {
    console.log('########/accessToken#######');
    console.log(req.body);
    const didInfo = req.body;
    const uDid = didInfo.did;
    const uPubKeyId = didInfo.publicKeyID;
    const signature = didInfo.signature;
    const data = JSON.stringify(didInfo.did);
    const exp = '60000ms';

    const didAuthResult = await finDID.didAuth({ 'keyType':didInfo.keyType,'pubKeyData' :didInfo.publicKey},signature,data)
    
    const isValid = didAuthResult;
    console.log(didAuthResult);

    if (!isValid) res.send("Error : The requestor's identity is not confirmed.");

    //accessToken과 endPoint 발급 
    const token = await jwt.genJWT(exp,didInfo)
    console.log(token);
    if(!token) res.send("Error : jwt not generated.");
    
    app.accessKeyDB.set(token.accessToken, token.accessKey);

    const accessPoint = {
        'accessToken':token.accessToken,
        'endPoint': ACCESS.VERIFIER+'/claimProp'
    }
    res.send(accessPoint);
      


});

app.post('/claimProp', async function(req, res){
    console.log('########/claimProp#######');
    console.log(req.body);
    const accessToken = req.body.accessToken; //accessToken
    const accessKey = app.accessKeyDB.get(accessToken);

    const isValid = await jwt.verifyJWT(accessToken,accessKey);
    if(!isValid) res.send('Not Valid Access Token');

    const claimProp = {}; // ui로 띄워야함
    const result = {
        'claimProp':'ui에 있는거 보내쇼',
        'endPoint': ACCESS.VERIFIER+'/vp'
    }
    res.send(result);

});

app.post('/vp', async function(req, res) {
    console.log('########/vp#######');
    console.log('req>> ' ,req.body);
    const vp = req.body.vp
    
    const auth_meta = {
        'verifier' :{
            'did':DID_INFO.SVC_DID,
            'pubKeyID':DID_INFO.SVC_PUBKEY_ID,
            'signature':await (await finDID.sign(DID_INFO.SVC_DID,DID_INFO.SVC_KEYTYPE,ACCOUNT.SVC_PRIVATE_KEY)).signature
        },
        'issuer' : {
            'did':vp.issuerdid,
            'pubKeyID':vp.issuerpkid
        },
        'user': {
            'did':vp.ownerdid,
            'pubKeyID':vp.ownerpkid
        }

    }

    //vp 검증 시작 
    let auth_info = await axios({
       url: ACCESS.DID_SERVICE+"/auth-info",
       method:"post",
       data: auth_meta //json
    });
    auth_info = auth_info.data
    console.log(auth_info); //auth_info.data

    let ciid = await axios({
        url: ACCESS.DID_SERVICE+'/get-vciid', 
        method:"post",
        data: {'cid':vp.cid} //json
     });
     ciid = ciid.data
     console.log(ciid); //auth_info.data

    //1) vp signature 검증
    const vpSig = vp.signature;
    const pid = vp.pid
    delete vp.signature;
    vp.pid = "";
    const isValid_vpSig = await finDID.didAuth({ 'keyType':auth_info.user.keyType,'pubKeyData' :auth_info.user.pubKey},vpSig,JSON.stringify(vp));
    vp.signature = vpSig;
    if(!isValid_vpSig) res.send('Not Valid VP Signature!');
    else console.log('success verify VP Signature!')

    //2) vp id 
    console.log(vp);
    const isValid_pid = (pid == await _createHash(vp));
    if(!isValid_pid) res.send("Not valid VP ID");
    else console.log('success verify VP ID');

    //3) claim 
    const claims = vp.claims
    var claim = Object.keys(claims); //key
    const infos = vp.infos
    var info = Object.keys(infos); //key
    for(i=0;i<claim.length;i++){
        var signData = claims[claim[i]]+ ciid; //value + ciid
        const isValid_claim = await finDID.didAuth({ 'keyType':auth_info.issuer.keyType,'pubKeyData' :auth_info.issuer.pubKey},infos[info[i]],JSON.stringify(signData));
        if(!isValid_claim) res.send('Not Valid claim');
        else console.log('success verify claim!');
    }

    res.send('success');

});

app.listen(PORT, function() {
  console.log('Express server listening on port ', PORT); // eslint-disable-line
});


