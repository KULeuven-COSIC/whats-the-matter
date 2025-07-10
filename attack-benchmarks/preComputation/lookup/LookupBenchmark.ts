import { createReadStream } from 'fs';
import { createInterface } from 'readline';
import { performance } from 'perf_hooks';
import { PbkdfParameters, Spake2p } from "../../../implementation-attacks/spake2p/crypto/Spake2p";
import { ByteArray } from "../../../implementation-attacks/spake2p/util/ByteArray";
import { Crypto } from "../../../implementation-attacks/spake2p/crypto/Crypto";
import { CryptoNode } from "../../../implementation-attacks/spake2p/crypto/CryptoNode"; 

// initializing the cryptographic provider
Crypto.get = () => new CryptoNode();

// helper function to calculate median
function calculateMedian(values: number[]): number {
    const sorted = values.slice().sort((a, b) => a - b);
    const mid = Math.floor(sorted.length / 2);
    return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
}

// helper function to calculate 95% confidence interval
function calculate95CI(values: number[]): { lower: number, upper: number } {
    const sorted = values.slice().sort((a, b) => a - b);
    const lowerIndex = Math.floor(0.025 * sorted.length);
    const upperIndex = Math.ceil(0.975 * sorted.length) - 1;
    return { lower: sorted[lowerIndex], upper: sorted[upperIndex] };
}

// function to compute w0 for a given passcode
async function computeW0(passcode: number, pbkdfParameters: PbkdfParameters): Promise<bigint> {
    const { w0 } = await Spake2p.computeW0W1(pbkdfParameters, passcode);
    return w0;
}

// function to look up w0 in the CSV file
async function findPasscodeByW0(w0: bigint, filePath: string): Promise<string | null> {
    return new Promise((resolve, reject) => {
        const fileStream = createReadStream(filePath);
        const rl = createInterface({
            input: fileStream,
            crlfDelay: Infinity,
        });

        let isFirstLine = true;

        rl.on('line', (line) => {
            if (isFirstLine) {
                // skipping the header
                isFirstLine = false;
                return;
            }

            const [passcode, w0Str] = line.split(',');
            if (w0Str && BigInt(w0Str) === w0) {
                resolve(passcode);
                rl.close();
            }
        });

        rl.on('close', () => resolve(null));
        rl.on('error', (err) => reject(err));
    });
}

// main function to select a random passcode, compute w0, and time the lookup
async function main() {
    const pbkdfParameters: PbkdfParameters = {
        iterations: 1000,
        salt: ByteArray.fromString('asalt'),
    };

    const timings: number[] = [];
    const iterations = 10;

    for (let i = 0; i < iterations; i++) {
        // selecting a new random passcode for each iteration
        const randomPasscode = Math.floor(Math.random() * 99999998) + 1;
        console.log(`Iteration ${i + 1}: Selected Passcode: ${randomPasscode}`);

        // computing w0 for the selected passcode
        const w0 = await computeW0(randomPasscode, pbkdfParameters);
        console.log(`Iteration ${i + 1}: Computed w0: ${w0}`);

        // timing the lookup in the CSV file
        const startTime = performance.now();
        const foundPasscode = await findPasscodeByW0(w0, 'snippet.csv'); // added table snippet for demonstration
        const endTime = performance.now();
        timings.push(endTime - startTime);

        if (foundPasscode) {
            console.log(`Iteration ${i + 1}: Found Passcode: ${foundPasscode}`);
        } else {
            console.log(`Iteration ${i + 1}: Passcode not found in table.`);
        }
    }

    // calculating statistics
    const median = calculateMedian(timings);
    const { lower, upper } = calculate95CI(timings);

    console.log(`Median lookup time: ${median.toFixed(2)} ms`);
    console.log(`95% Confidence Interval: [${lower.toFixed(2)} ms, ${upper.toFixed(2)} ms]`);
}

main().catch((err) => console.error(err));