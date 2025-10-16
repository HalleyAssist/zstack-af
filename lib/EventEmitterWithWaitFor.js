'use strict';

const EventEmitter = require('events');

/**
 * EventEmitterWithWaitFor extends Node.js EventEmitter with waitFor method
 * 
 * This class provides backward compatibility with eventemitter2's waitFor feature
 * while using the standard Node.js EventEmitter as the base.
 * 
 * The waitFor method returns a cancelable promise that resolves when a specific
 * event is emitted. It supports:
 * - Timeout: automatically reject if event doesn't occur within specified time
 * - Filter: only resolve for events that match a filter function
 * - Cancellation: cancel the wait and clean up listeners
 * 
 * All standard EventEmitter methods (on, emit, off, once, etc.) work as expected.
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
        let rejectPromise;
        let isSettled = false;

        const promise = new Promise((resolve, reject) => {
            rejectPromise = reject;
            
            listener = function(...args) {
                // If there's a filter, check if the event should be handled
                if (filter && !filter.apply(this, args)) {
                    return;
                }
                
                cleanup();
                isSettled = true;
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
                    isSettled = true;
                    const err = new Error(`waitFor timed out after ${timeout}ms waiting for event: ${event}`);
                    err.code = 'ETIMEDOUT';
                    reject(err);
                }, timeout);
            }
        });

        // Add cancel method to the promise
        promise.cancel = () => {
            if (!isSettled) {
                cleanup();
                isSettled = true;
                const err = new Error('canceled');
                rejectPromise(err);
            }
        };

        return promise;
    }
}

module.exports = EventEmitterWithWaitFor;
