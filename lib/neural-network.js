// Phish Shield - Pure JS Deep Neural Network (CSP-safe, no eval)
// Architecture: input → 64 → 32 → 16 → 1 (ReLU + Dropout + Sigmoid)

class DeepNeuralNetwork {
    constructor(inputSize, hiddenLayers = [64, 32, 16]) {
        this.inputSize = inputSize;
        this.layerSizes = [inputSize, ...hiddenLayers, 1];
        this.layers = [];

        for (let i = 0; i < this.layerSizes.length - 1; i++) {
            const inDim = this.layerSizes[i];
            const outDim = this.layerSizes[i + 1];
            this.layers.push({
                W: this.initWeights(inDim, outDim),
                b: new Array(outDim).fill(0)
            });
        }
    }

    initWeights(inDim, outDim) {
        const scale = Math.sqrt(2 / inDim);
        return Array.from({ length: inDim }, () =>
            Array.from({ length: outDim }, () => (Math.random() * 2 - 1) * scale)
        );
    }

    static relu(x) { return x > 0 ? x : 0; }
    static reluDeriv(z) { return z > 0 ? 1 : 0; }
    static sigmoid(x) {
        x = Math.max(-20, Math.min(20, x));
        return 1 / (1 + Math.exp(-x));
    }

    static shuffle(arr) {
        for (let i = arr.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [arr[i], arr[j]] = [arr[j], arr[i]];
        }
        return arr;
    }

    linearForward(a, layer) {
        const out = new Array(layer.b.length).fill(0);
        for (let j = 0; j < layer.b.length; j++) {
            let sum = layer.b[j];
            for (let i = 0; i < a.length; i++) sum += a[i] * layer.W[i][j];
            out[j] = sum;
        }
        return out;
    }

    getDropoutRate(layerIndex) {
        if (layerIndex === 0) return 0.3;
        if (layerIndex === 1) return 0.25;
        return 0.15;
    }

    forward(input, training = false) {
        this.fwdCache = { a: [input], z: [] };
        let a = input;

        for (let l = 0; l < this.layers.length; l++) {
            const z = this.linearForward(a, this.layers[l]);
            this.fwdCache.z.push(z);

            if (l < this.layers.length - 1) {
                a = z.map(DeepNeuralNetwork.relu);
                if (training) {
                    const rate = this.getDropoutRate(l);
                    a = a.map((v) => (Math.random() < rate ? 0 : v / (1 - rate)));
                }
            } else {
                a = z.map(DeepNeuralNetwork.sigmoid);
            }
            this.fwdCache.a.push(a);
        }
        return a[0];
    }

    backwardSingle(target) {
        const L = this.layers.length;
        const grads = this.layers.map((layer) => ({
            W: layer.W.map((row) => row.map(() => 0)),
            b: layer.b.map(() => 0)
        }));

        let delta = [this.fwdCache.a[L][0] - target];

        for (let l = L - 1; l >= 0; l--) {
            const aPrev = this.fwdCache.a[l];
            for (let j = 0; j < delta.length; j++) {
                grads[l].b[j] += delta[j];
                for (let i = 0; i < aPrev.length; i++) {
                    grads[l].W[i][j] += aPrev[i] * delta[j];
                }
            }
            if (l > 0) {
                const zBelow = this.fwdCache.z[l - 1];
                const newDelta = new Array(aPrev.length).fill(0);
                for (let i = 0; i < aPrev.length; i++) {
                    let sum = 0;
                    for (let j = 0; j < delta.length; j++) {
                        sum += this.layers[l].W[i][j] * delta[j];
                    }
                    newDelta[i] = sum * DeepNeuralNetwork.reluDeriv(zBelow[i]);
                }
                delta = newDelta;
            }
        }
        return grads;
    }

    applyGradients(grads, lr, batchSize) {
        const scale = lr / batchSize;
        for (let l = 0; l < this.layers.length; l++) {
            for (let i = 0; i < this.layers[l].W.length; i++) {
                for (let j = 0; j < this.layers[l].W[i].length; j++) {
                    this.layers[l].W[i][j] -= scale * grads[l].W[i][j];
                }
            }
            for (let j = 0; j < this.layers[l].b.length; j++) {
                this.layers[l].b[j] -= scale * grads[l].b[j];
            }
        }
    }

    zeroGrads() {
        return this.layers.map((layer) => ({
            W: layer.W.map((row) => row.map(() => 0)),
            b: layer.b.map(() => 0)
        }));
    }

    accumulateGrads(total, addition) {
        for (let l = 0; l < this.layers.length; l++) {
            for (let i = 0; i < total[l].W.length; i++) {
                for (let j = 0; j < total[l].W[i].length; j++) {
                    total[l].W[i][j] += addition[l].W[i][j];
                }
            }
            for (let j = 0; j < total[l].b.length; j++) {
                total[l].b[j] += addition[l].b[j];
            }
        }
    }

    train(X, y, options = {}) {
        const epochs = options.epochs || 100;
        const lr = options.lr || 0.05;
        const batchSize = options.batchSize || 16;
        const n = X.length;
        const history = { loss: [], accuracy: [] };

        for (let epoch = 0; epoch < epochs; epoch++) {
            const indices = DeepNeuralNetwork.shuffle([...Array(n).keys()]);
            let epochLoss = 0;

            for (let start = 0; start < n; start += batchSize) {
                const batchGrad = this.zeroGrads();
                let count = 0;

                for (let b = start; b < Math.min(start + batchSize, n); b++) {
                    const idx = indices[b];
                    const pred = this.forward(X[idx], true);
                    const yVal = y[idx];
                    const loss = -(yVal * Math.log(pred + 1e-8) + (1 - yVal) * Math.log(1 - pred + 1e-8));
                    epochLoss += loss;

                    const grads = this.backwardSingle(yVal);
                    this.accumulateGrads(batchGrad, grads);
                    count++;
                }

                this.applyGradients(batchGrad, lr, count);
            }

            let correct = 0;
            for (let i = 0; i < n; i++) {
                const pred = this.forward(X[i], false);
                const predicted = pred >= 0.5 ? 1 : 0;
                if (predicted === y[i]) correct++;
            }

            history.loss.push(epochLoss / n);
            history.accuracy.push(correct / n);

            if (options.onEpochEnd) {
                options.onEpochEnd(epoch, history);
            }
        }

        return history;
    }

    predict(input) {
        return this.forward(input, false);
    }

    evaluate(X, y) {
        let correct = 0;
        for (let i = 0; i < X.length; i++) {
            const pred = this.predict(X[i]) >= 0.5 ? 1 : 0;
            if (pred === y[i]) correct++;
        }
        return correct / X.length;
    }

    serialize() {
        return {
            inputSize: this.inputSize,
            layerSizes: this.layerSizes,
            layers: this.layers.map((l) => ({ W: l.W, b: l.b }))
        };
    }

    static deserialize(data) {
        const nn = new DeepNeuralNetwork(data.inputSize, data.layerSizes.slice(1, -1));
        nn.layers = data.layers.map((l) => ({
            W: l.W,
            b: l.b
        }));
        return nn;
    }
}

if (typeof self !== 'undefined') self.DeepNeuralNetwork = DeepNeuralNetwork;
