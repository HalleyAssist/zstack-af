'use strict';

const EventEmitter = require('events');

/**
 * Extends Node.js EventEmitter with waitFor method for backward compatibility
 * with eventemitter2
 */
class EventEmitterWithWaitFor extends EventEmitter {
    /**
     * Wait for an event to be emitted
     * @param {string} event - The event name to wait for
     * @param {number|Object} options - Timeout in ms or options object with {timeout, filter}
     * @returns {Promise} A cancelable promise that resolves when the event is emitted
     */
    waitFor(event, options) {
        let timeout = 0;
        let filter;

        // Handle options parameter
        if (typeof options === 'number') {
            timeout = options;
        } else if (typeof options === 'function') {
            filter = options;
        } else if (typeof options === 'object' && options !== null) {
            timeout = options.timeout || 0;
            filter = options.filter;
        }

        let timeoutId;
        let listener;
        let cleanup;

        const promise = new Promise((resolve, reject) => {
            listener = function(...args) {
                // If there's a filter, check if the event should be handled
                if (filter && !filter.apply(this, args)) {
                    return;
                }
                
                cleanup();
                resolve(args);
            };

            cleanup = () => {
                if (timeoutId) {
                    clearTimeout(timeoutId);
                    timeoutId = null;
                }
                this.off(event, listener);
            };

            this.on(event, listener);

            if (timeout > 0) {
                timeoutId = setTimeout(() => {
                    cleanup();
                    const err = new Error(`waitFor timed out after ${timeout}ms waiting for event: ${event}`);
                    err.code = 'ETIMEDOUT';
                    reject(err);
                }, timeout);
            }
        });

        // Add cancel method to the promise
        promise.cancel = () => {
            cleanup();
            // Just clean up the listener when canceled
            promise.catch(() => {});
        };

        return promise;
    }
}

module.exports = EventEmitterWithWaitFor;
