import { EventEmitter } from "events";

export const VERSION: number;
export const HEADER_SIZE: number;
export const FLAG_ENCRYPTED: number;

export const PacketType: {
  readonly HELLO: number;
  readonly HELLO_ACK: number;
  readonly PING: number;
  readonly PONG: number;
  readonly DISCOVER: number;
  readonly PEER_LIST: number;
  readonly DHT_PUT: number;
  readonly DHT_GET: number;
  readonly DHT_RES: number;
  readonly MSG: number;
  readonly PUBSUB_SUB: number;
  readonly PUBSUB_PUB: number;
  readonly FILE_OFFER: number;
  readonly FILE_CHUNK: number;
  readonly FILE_ACK: number;
  readonly TUNNEL_OPEN: number;
  readonly TUNNEL_DATA: number;
  readonly TUNNEL_CLOSE: number;
  readonly HOLE_PUNCH: number;
};

export function generatePeerId(seed?: string): string;
export function encryptPayload(plaintextBuf: Buffer, networkKey: string, nonceHex?: string | null): Buffer;
export function decryptPayload(encryptedJsonBuf: Buffer, networkKey: string): Buffer;
export function signEnvelope(envelope: Record<string, any>, networkKey: string): string;
export function verifyEnvelope(envelope: Record<string, any>, networkKey: string): boolean;
export function encodeFrame(msgType: number, envelope: Record<string, any>, options?: { encrypt?: boolean; networkKey?: string; flags?: number; nonceHex?: string }): Buffer;
export function decodeFrame(frameBuf: Buffer, networkKey?: string): { msgType: number; flags: number; envelope: Record<string, any> };
export function xorDistance(idA: string, idB: string): bigint;

export class DHTNode {
  constructor(selfPeerId: string, kBucketSize?: number);
  put(key: string, value: any, origin?: string, ttlSec?: number): Record<string, any>;
  get(key: string): any;
  closestPeers(targetKeyOrId: string, count?: number): Array<Record<string, any>>;
}

export interface AdvanceTetherNodeOptions {
  name?: string;
  lang?: string;
  host?: string;
  port?: number;
  udpPort?: number;
  networkKey?: string;
  peerId?: string;
  encrypt?: boolean;
  downloadDir?: string;
}

export class AdvanceTetherNode extends EventEmitter {
  peerId: string;
  name: string;
  lang: string;
  host: string;
  port: number;
  udpPort: number;
  dht: DHTNode;
  constructor(options?: AdvanceTetherNodeOptions);
  start(): Promise<{ host: string; port: number; udpPort: number }>;
  stop(): Promise<void>;
  connect(host: string, port: number, timeoutMs?: number): Promise<string>;
  sendMessage(peerId: string, text: string, rpc?: string | null, extra?: Record<string, any>): boolean;
  ping(peerId: string): boolean;
  dhtPut(key: string, value: any): Record<string, any>;
  dhtGet(key: string): any;
  subscribe(topic: string): void;
  publish(topic: string, data: any): number;
  sendFileBytes(peerId: string, filename: string, contentBuf: Buffer, chunkSize?: number): string | null;
  openTunnel(peerId: string, targetHost?: string, targetPort?: number): string | null;
  sendTunnelData(peerId: string, tunnelId: string, dataBuf: Buffer, echo?: boolean): boolean;
  closeTunnel(peerId: string, tunnelId: string): boolean;
}
