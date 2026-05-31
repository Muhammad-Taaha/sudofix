class JobManager {
    constructor() {
        this.data = [];
        this.cleanups = [];
    }

    addData(item) {
        this.data.push(item);
    }

    dataCount() {
        return this.data.length;
    }

    // VULN-2: Capture of index after slice may reallocate – use of stale reference
    scheduleCleanup(index) {
        if (index >= this.data.length) return;
        const ref = this.data[index];        // reference to string (strings are immutable, but we use as example)
        this.cleanups.push(() => {
            // If this.data has been cleared or reordered, ref is still valid string,
            // but the semantic vulnerability would be if ref was an object that was mutated elsewhere.
            console.log(`Cleaning chunk: ${ref}`);
        });
    }

    runCleanup() {
        for (const fn of this.cleanups) {
            fn();
        }
    }
}

module.exports = JobManager;