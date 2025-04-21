import cors from '@fastify/cors'
import { WebSocket } from '@fastify/websocket'
import spawn from 'child_process'
import fastify, { FastifyReply, FastifyRequest } from 'fastify'
import { isIP } from 'net'
import { promises as dns } from 'dns'
import { z } from "zod"
import ipaddr from 'ipaddr.js'

type NetworkToolType = 'mtr' | 'traceroute' | 'ping' | 'bgp'

interface NetworkToolConfig {
    command: string
    args: (target: string) => string[]
    enabled: boolean
}

const NETWORK_TOOLS: Record<NetworkToolType, NetworkToolConfig> = {
    mtr: {
        command: 'mtr',
        args: (target) => ['-c', '5', '-r', '-w', '-b', target],
        enabled: process.env.PINGTRACE_ENABLED === 'true'
    },
    traceroute: {
        command: 'traceroute',
        args: (target) => ['-w', '1', '-q', '1', target],
        enabled: process.env.PINGTRACE_ENABLED === 'true'
    },
    ping: {
        command: 'ping',
        args: (target) => ['-c', '5', target],
        enabled: process.env.PINGTRACE_ENABLED === 'true'
    },
    bgp: {
        command: 'birdc',
        args: (target) => ['-r', 'sh', 'ro', 'all', 'for', target],
        enabled: process.env.BGP_ENABLED === 'true'
    }
}

const BOGON_PREFIXES = [
    '::/8',
    '64:ff9b::/96',
    '100::/8',
    '200::/7',
    '400::/6',
    '800::/5',
    '1000::/4',
    '2001::/33',
    '2001:0:8000::/33',
    '2001:2::/48',
    '2001:3::/32',
    '2001:10::/28',
    '2001:20::/28',
    '2001:db8::/32',
    '2002::/16',
    '3ffe::/16',
    '4000::/3',
    '5f00::/8',
    '6000::/3',
    '8000::/3',
    'a000::/3',
    'c000::/3',
    'e000::/4',
    'f000::/5',
    'f800::/6',
    'fc00::/7',
    'fe80::/10',
    'fec0::/10',
    'ff00::/8'
].map(prefix => {
    const [addr, len] = prefix.split('/')
    return { prefix: ipaddr.IPv6.parse(addr), length: parseInt(len) }
})

const isBogonPrefix = (target: string): boolean => {
    try {
        const [addr, len] = target.split('/')
        const parsed = ipaddr.IPv6.parse(addr)
        const prefixLen = len ? parseInt(len) : 128

        return BOGON_PREFIXES.some(bogon => {
            if (prefixLen < bogon.length) return false
            const targetPrefix = parsed.match(bogon.prefix, bogon.length)
            return targetPrefix
        })
    } catch {
        return true
    }
}

const validateIPv6Target = async (target: string): Promise<string | null> => {
    if (isIP(target.split('/')[0]) === 4) {
        return "IPv4 addresses are not allowed. Please provide an IPv6 address."
    }

    if (!isIP(target.split('/')[0])) {
        try {
            const records = await dns.resolve6(target)
            if (!records?.length) {
                return "The provided domain only resolves to IPv4 (A record). Please use a domain with an AAAA record for IPv6."
            }
            target = records[0]
        } catch {
            return "Failed to resolve AAAA record for the domain. Ensure the domain has a valid IPv6 address."
        }
    }

    if (isBogonPrefix(target)) {
        return "Bogon prefix detected. Queries for bogon prefixes are not allowed."
    }

    return null
}

const executeNetworkTool = (type: NetworkToolType, target: string): { data?: string, error?: string } => {
    const tool = NETWORK_TOOLS[type]
    if (!tool.enabled) {
        return { error: `${type.toUpperCase()} is disabled` }
    }

    const result = spawn.spawnSync(tool.command, tool.args(target))
    const output = result.stdout?.toString() || result.stderr?.toString()
    return { data: output }
}

const server = fastify()
server.register(cors, {
    origin: process.env.CORS_ORIGIN || "*"
})
server.register(import('@fastify/websocket'))
server.register(import('@fastify/rate-limit'), {
    max: 30,
    timeWindow: '1 minute'
})

server.get('/', async (request: FastifyRequest, reply: FastifyReply) => {
    return reply.status(200).send({ "message": "https://github.com/vojkovic/confetti" })
})

server.register(async function (fastify) {
    fastify.get('/latency', { websocket: true }, async (connection: WebSocket, request: FastifyRequest) => {
        const remoteIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress
        console.log(`[${new Date()}][LATENCY] websocket connected from ${remoteIp}`)
        connection.on('message', (message: string) => {
            connection.send(message.toString())
        })
        connection.on('close', () => {
            console.log(`[${new Date()}][LATENCY] websocket disconnected from ${remoteIp}`)
        })
    })
})

const requestSchema = z.object({
    type: z.enum(['mtr', 'traceroute', 'ping', 'bgp']),
    target: z.string().trim()
})

server.post('/lg', async (request: FastifyRequest, reply: FastifyReply) => {
    const validation = requestSchema.safeParse(request.body)
    if (!validation.success) {
        return reply.status(400).send({ error: validation.error })
    }

    const { type, target } = validation.data
    const remoteIp = request.headers['x-forwarded-for'] || request.socket.remoteAddress
    console.log(`[${new Date()}][LG] ${type} ${target} from ${remoteIp}`)

    if (type === 'bgp' && !target.includes('/')) {
        return reply.status(400).send({ error: "BGP queries require CIDR notation" })
    }

    const error = await validateIPv6Target(target)
    if (error) {
        return reply.status(403).send({ error })
    }

    const result = executeNetworkTool(type, target)
    if (result.error) {
        return reply.status(400).send({ error: result.error })
    }

    return reply.status(200).send({ data: result.data })
})

server.listen({ port: 33046, host: "::1" }, (err: any, address: string) => {
    if (err) {
        console.error(err)
        process.exit(1)
    }
    console.log(`Server listening at ${address}`)
})
