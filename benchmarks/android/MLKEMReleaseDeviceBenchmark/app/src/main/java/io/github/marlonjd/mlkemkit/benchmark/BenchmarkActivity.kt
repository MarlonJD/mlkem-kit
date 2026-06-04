package io.github.marlonjd.mlkemkit.benchmark

import android.app.Activity
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import io.github.marlonjd.mlkemnative.MLKEMNative768
import java.time.Instant
import org.json.JSONArray
import org.json.JSONObject

class BenchmarkActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)

        Thread {
            try {
                val json = MLKEMReleaseDeviceBenchmark.run()
                Log.i(TAG, "MLKEM_BENCHMARK_JSON_BEGIN")
                Log.i(TAG, json.toString(2))
                Log.i(TAG, "MLKEM_BENCHMARK_JSON_END")
                finishAndRemoveTask()
                Runtime.getRuntime().exit(0)
            } catch (exception: Throwable) {
                Log.e(TAG, "ML-KEM benchmark failed", exception)
                finishAndRemoveTask()
                Runtime.getRuntime().exit(1)
            }
        }.start()
    }

    private companion object {
        const val TAG = "MLKEMBenchmark"
    }
}

private object MLKEMReleaseDeviceBenchmark {
    private const val WARMUP_COUNT = 10
    private const val SAMPLE_COUNT = 200

    fun run(): JSONObject {
        var peakAllocatedBytes = allocatedBytes()
        var accumulator = 0

        fun observePeak() {
            peakAllocatedBytes = maxOf(peakAllocatedBytes, allocatedBytes())
        }

        val keyGenerationMs = measure {
            val privateKey = MLKEMNative768.PrivateKey.generate()
            accumulator = accumulator xor privateKey.publicKey.rawRepresentation[0].toInt()
            observePeak()
        }

        val encapsulationKey = MLKEMNative768.PrivateKey.generate()
        val publicKey = encapsulationKey.publicKey
        val encapsulationMs = measure {
            val encapsulation = publicKey.encapsulate()
            accumulator = accumulator xor encapsulation.ciphertext[0].toInt()
            observePeak()
        }

        val decapsulationKey = MLKEMNative768.PrivateKey.generate()
        val ciphertexts = Array(SAMPLE_COUNT) {
            decapsulationKey.publicKey.encapsulate().ciphertext
        }
        var decapsulationIndex = 0
        val decapsulationMs = measure {
            val sharedSecret = decapsulationKey.decapsulate(ciphertexts[decapsulationIndex])
            decapsulationIndex = (decapsulationIndex + 1) % ciphertexts.size
            accumulator = accumulator xor sharedSecret[0].toInt()
            observePeak()
        }

        observePeak()
        if (accumulator == Int.MIN_VALUE) {
            Log.w("MLKEMBenchmark", "unreachable accumulator value")
        }

        val result = JSONObject()
            .put("platform", "Android")
            .put("device", System.getenv("MLKEM_BENCHMARK_DEVICE") ?: "Android emulator ${Build.MODEL}")
            .put("osOrRuntime", System.getenv("MLKEM_BENCHMARK_OS") ?: "Android ${Build.VERSION.RELEASE} (API ${Build.VERSION.SDK_INT})")
            .put("buildConfiguration", "release")
            .put("providerId", "kotlin-pure-mlkem768")
            .put("keyGenerationP50Ms", percentile50(keyGenerationMs))
            .put("encapsulationP50Ms", percentile50(encapsulationMs))
            .put("decapsulationP50Ms", percentile50(decapsulationMs))
            .put("peakAllocationBytes", peakAllocatedBytes)
            .put("sampleCount", SAMPLE_COUNT)
            .put("measuredAt", Instant.now().toString())

        return JSONObject()
            .put("schemaVersion", 1)
            .put("status", "partial")
            .put("results", JSONArray().put(result))
    }

    private fun measure(operation: () -> Unit): List<Double> {
        repeat(WARMUP_COUNT) {
            operation()
        }

        return List(SAMPLE_COUNT) {
            val start = SystemClock.elapsedRealtimeNanos()
            operation()
            val end = SystemClock.elapsedRealtimeNanos()
            (end - start).toDouble() / 1_000_000.0
        }
    }

    private fun percentile50(values: List<Double>): Double {
        return values.sorted()[values.size / 2]
    }

    private fun allocatedBytes(): Long {
        val runtime = Runtime.getRuntime()
        return runtime.totalMemory() - runtime.freeMemory()
    }
}
