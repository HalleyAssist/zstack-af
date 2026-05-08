export class WaitForOptions {
    timeout?: number;
    filter?: (...args: unknown[]) => boolean;
}

export class IndirectSendConfig {
    dstAddr: number;
    retries?: number;
    indirectTimeout: number;
    completeTimeout?: number;
    signalTimeout?: { promise: Promise<unknown> };
}

export class AfExtOptions {
    options?: number;
    radius?: number;
    dstEpId?: number;
    dstPanId?: number;
}

export class AfSendOptions {
    options?: number;
    radius?: number;
    timeout?: number;
    retries?: number;
}

export class ZclFrameControl {
    frameType: number;
    manufSpec: number;
    direction: number;
    disDefaultRsp: number;
}

export class ZclRequestConfig {
    manufSpec?: number;
    direction?: number;
    disDefaultRsp?: number;
    seqNum?: number;
    afOptions?: AfSendOptions;
    skipQos?: boolean;
    response?: boolean;
}