import { EventEmitter } from 'events';
import { FileHandle } from 'fs/promises';

// Re-export shared option types
export {
    WaitForOptions,
    IndirectSendConfig,
    AfExtOptions,
    AfSendOptions,
    ZclFrameControl,
    ZclRequestConfig,
} from './lib/types';

// ---------------------------------------------------------------------------
// EventEmitterWithWaitFor
// ---------------------------------------------------------------------------

export class EventEmitterWithWaitFor extends EventEmitter {
    /**
     * Wait for an event to be emitted.
     * @param event   The event name to wait for.
     * @param options Timeout (ms), a filter function, or an options object.
     * @returns A cancelable promise that resolves with the event arguments array.
     */
    waitFor(
        event: string,
        options?: number | ((...args: any[]) => boolean) | import('./lib/types').WaitForOptions,
    ): Promise<any[]> & { cancel(): void };
}

// ---------------------------------------------------------------------------
// AfError
// ---------------------------------------------------------------------------

export class AfError extends Error {
    code: number | string;
    constructor(code: number | string);
}

// ---------------------------------------------------------------------------
// AfQos (Qos)
// ---------------------------------------------------------------------------

export class AfQos {
    execute<T>(fn: () => Promise<T> | T, ...args: any[]): Promise<T>;
}

// ---------------------------------------------------------------------------
// AfController
// ---------------------------------------------------------------------------

export class AfController extends EventEmitterWithWaitFor {
    /** Current transaction counter. */
    _trans: number;

    constructor();

    /** Returns a map of event-name → listener count. */
    eventListenerCount(): Record<string, number>;

    /** Increment and return the next Zigbee transaction ID (1–255). */
    nextTransId(): number;

    /**
     * Returns true when the given destination address should be reached via
     * indirect (source-routed / retried) sending.  Overridden by subclasses.
     */
    shouldSendIndrect(dstAddr: number): boolean;

    /**
     * Retry-loop wrapper for indirect sends.
     * @param sendFn Function that performs a single send attempt.
     * @param cfg    Indirect-send configuration.
     */
    indirectSend(
        sendFn: (attempt: number, canSrcRtg: boolean) => Promise<unknown>,
        cfg: import('./lib/types').IndirectSendConfig,
    ): Promise<any>;

    /**
     * Convenience wrapper – builds an {@link IndirectSendConfig} from `cfg`
     * and forwards additional arguments to `this.request(...)`.
     */
    indirectRequestSend(
        cfg: import('./lib/types').IndirectSendConfig,
        ...args: any[]
    ): Promise<any>;
}

export class MsgHandler {
    evt: string;
    hdlr: string;
}

// ---------------------------------------------------------------------------
// Af
// ---------------------------------------------------------------------------

export class Af extends EventEmitterWithWaitFor {
    /** Underlying controller (AfController or compatible). */
    _controller: any;
    /** Current ZCL sequence number (0–252). */
    _seq: number;
    /** Default timeout (ms) for indirect AF sends. */
    indirectTimeout: number;
    /** Default resend timeout (ms). */
    resendTimeout: number;
    /** Maximum number of concurrent in-flight transactions. */
    maxTransactions: number;
    /** QoS execution wrapper. */
    qos: AfQos;

    static msgHandlers: MsgHandler[];

    constructor(controller: any, qos?: AfQos | null);

    emit(eventName: string | symbol, ...args: any[]): boolean;

    /** Return and increment the ZCL sequence number. */
    nextZclSeqNum(): number;

    /**
     * Route an incoming AF message to the correct endpoint handler and
     * re-emit it on the ZCL event bus.
     */
    dispatchIncomingMsg(
        targetEp: any,
        remoteEp: any,
        type: 'dataConfirm' | 'reflectError' | 'incomingMsg' | 'incomingMsgExt',
        msg: any,
    ): any;

    /** Build extended AF params for a raw payload. */
    makeAfParamsExt(
        srcEp: any,
        addrMode: number,
        dstAddrOrGrpId: number | string,
        cId: number,
        rawPayload: Buffer,
        opt?: import('./lib/types').AfExtOptions,
    ): any;

    /** Build standard AF params for a raw payload. */
    makeAfParams(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        rawPayload: Buffer,
        opt?: import('./lib/types').AfSendOptions,
    ): any;

    /** Low-level send with cancellation support. */
    _send(
        cancellationState: { addOnCancel(fn: () => void): void },
        srcEp: any,
        dstEp: any,
        cId: number | string,
        rawPayload: Buffer,
        opt?: import('./lib/types').AfSendOptions,
    ): Promise<any>;

    /** High-level send (creates a cancellation state internally). */
    send(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        rawPayload: Buffer,
        opt?: import('./lib/types').AfSendOptions,
    ): Promise<any>;

    /** Cancel a pending AREQ promise gracefully. */
    static areqCancel(areq: Promise<unknown[]> & { cancel(): void }): Promise<void>;

    // --- ZCL Foundation ---

    _zclFoundation(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        cmd: number | string,
        zclData: Record<string, unknown> | unknown[],
        cfg: import('./lib/types').ZclRequestConfig,
    ): Promise<any>;

    zclFoundation(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        cmd: number | string,
        zclData: Record<string, unknown> | unknown[],
        cfg?: import('./lib/types').ZclRequestConfig,
    ): Promise<any>;

    // --- ZCL Functional ---

    _zclFunctional(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        cmd: number | string,
        zclData: Record<string, unknown> | unknown[],
        cfg: import('./lib/types').ZclRequestConfig,
    ): Promise<any>;

    zclFunctional(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        cmd: number | string,
        zclData: Record<string, unknown> | unknown[],
        cfg?: import('./lib/types').ZclRequestConfig,
    ): Promise<any>;

    // --- Cluster / attribute discovery ---

    zclClustersReq(
        srcEp: any,
        dstEp: any,
        eventEmitter?: EventEmitter,
        interested?: true | Record<string, unknown>,
    ): Promise<any>;

    zclClusterAttrsReq(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        interestedValue?: boolean,
    ): Promise<any>;

    _zclClusterAttrsReq(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        interestedValue?: boolean,
    ): Promise<any>;

    zclReadAllAttributes(
        srcEp: any,
        dstEp: any,
        cId: number | string,
        attrIds: number[],
    ): Promise<any[]>;

    zclClusterAttrIdsReq(
        srcEp: any,
        dstEp: any,
        cId: number | string,
    ): Promise<number[]>;

    // --- Helpers ---

    /** Parse a relay list buffer into an array of network addresses. */
    static parseRelayList(buf: Buffer): number[];

    /** Build AF source-route params from a relay list. */
    static buildAfSrcRtg(relayList: number[]): { relaycount: number; relaylist: number[] };
}

// ---------------------------------------------------------------------------
// Packet (zcl)
// ---------------------------------------------------------------------------

/** ZCL frame encode/decode utilities. */
export interface Packet {
    /** Parse a raw ZCL buffer into a structured object. */
    parse(zclBuf: Buffer, clusterId?: any): any;
    /** Encode a ZCL frame to a Buffer. */
    frame(
        frameCntl: any,
        manufCode: number,
        seqNum: number,
        cmd: any,
        zclPayload: any,
        clusterId?: any,
    ): Buffer;
    /** Parse only the ZCL frame header from a buffer. */
    header(buf: Buffer): any;
    /** FuncPayload constructor (functional frame encoder/decoder). */
    Functional: new (clusterId: number | string, direction: number, cmd: number | string) => any;
}

export const Packet: Packet;

// ---------------------------------------------------------------------------
// Ota
// ---------------------------------------------------------------------------

export class Ota {
    /** Read and validate an OTA firmware file header. */
    static readOtaHeader(fd: FileHandle): Promise<Record<string, unknown>>;
}
