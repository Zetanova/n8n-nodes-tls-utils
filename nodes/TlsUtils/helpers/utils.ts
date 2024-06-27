import { connect, CipherNameAndProtocol, ConnectionOptions, PeerCertificate, checkServerIdentity } from "tls";

export interface TlsEntry {
	host:string, //host or ip address to connect
	port:number,
	servername?:string, //SNI
	ca?: string[]|string //ca chain base64
	//todo proxy
}

export type TlsStatus = 'valid'|'expiring'|'expired'|'invalid'|'error'

export interface TestResult {
    date:string,
    servername:string,
    status:TlsStatus
    validTo:string,
    graceDate:string
}

export async function testTls(entry:TlsEntry, gracePeriod:number = 0.1) {
    const now = Date.now()

    const tlsResult = await getTls(entry)

    let status:TlsStatus = "valid";

    if(!tlsResult.cert) {
        return <TestResult> {
            date: new Date(now).toISOString(),
            servername: tlsResult.servername,
            status: 'error',
            validTo: '',
            graceDate: '',
        }
    }

    const validFrom = Date.parse(tlsResult.cert.valid_from)
    const validTo = Date.parse(tlsResult.cert.valid_to)

    const validPeriod = validTo - validFrom
    const graceDate = validTo - (validPeriod*gracePeriod)

    if(validTo < now || tlsResult.error?.message === 'CERT_HAS_EXPIRED') {
        status = "expired"
    } else if(tlsResult.error) {
        status = "invalid"
    } else if(graceDate < now) {
        status = "expiring"
    }

    const result:TestResult = {
        date: new Date(now).toISOString(),
        servername: tlsResult.servername,
        status: status,
        validTo: new Date(validTo).toISOString(),
        graceDate: new Date(graceDate).toISOString(),
    }

    return result
}

interface TlsResult {
    servername:string,
    cert?:PeerCertificate,
    error?:Error,
    cipher?:CipherNameAndProtocol
}

async function getTls(entry:TlsEntry) {

    //https://nodejs.org/api/tls.html#tlsconnectoptions-callback
    const options:ConnectionOptions = {
        host: entry.host,
        port: entry.port,
        servername: entry.servername,
        //todo secureContext
        checkServerIdentity: (hostname:string,cert:PeerCertificate) => {
            //console.debug("check server identity")
            return undefined
        },
        rejectUnauthorized: false,
        ca: entry.ca
    }


    const socket = connect(options)

    const connected = new Promise<TlsResult>((resolve,reject) => {

        socket.once('secureConnect', () => {
            //console.debug("secure connected")

            const serverName = options.servername ?? options.host ?? ''
            const peerCert = socket.getPeerCertificate(true)

            //const cert = new X509Certificate(peerCert.raw)
            //const checkedHost = cert.checkHost(serverName)

            const validation = checkServerIdentity(serverName, peerCert)

            resolve({
                servername: serverName,
                cert: peerCert,
                error: validation,
                cipher: socket.getCipher()
            })
        })
        socket.once('error', reject)
    })


    //socket.on('error', (err:Error) => console.debug('tls error', err))
    //socket.on('tlsClientError', () => console.debug('tlsClientError'))
    //socket.on('keylog', (args) => console.debug('keylog'))
    //socket.on('end', () => console.debug('tls end'))
    // socket.on('OCSPResponse', () => {
    //     console.log('OCSPResponse');
    // });

    //const completed = new Promise((resolve,reject) => socket.once('end', resolve))
    //await completed

    try {
        const result = await connected

        return result
    } catch(err) {
        return <TlsResult>{
            servername: entry.servername ?? entry.host,
            error: err
        }
    } finally {
        socket.destroySoon()
    }
}
