#include "archive/cdc.hpp"

#include "archive/chunk.hpp"

namespace bale::archive {

Result<void> validateCdcParams(const CdcParams& params) {
    if (params.min < minChunkSize || params.min > maxChunkSize) {
        return fail(ErrorKind::LimitExceeded, "cdc chunk min outside the supported range");
    }
    if (params.target < minChunkSize || params.target > maxChunkSize) {
        return fail(ErrorKind::LimitExceeded, "cdc chunk target outside the supported range");
    }
    if (params.max < minChunkSize || params.max > maxChunkSize) {
        return fail(ErrorKind::LimitExceeded, "cdc chunk max outside the supported range");
    }
    if (params.min > params.target || params.target > params.max) {
        return fail(ErrorKind::LimitExceeded, "cdc chunk sizes out of order: min, target, max");
    }
    return {};
}

CdcSplitter::CdcSplitter(const CdcParams& params) : params_(params) {
    bool powerOfTwo = params_.target != 0 && (params_.target & (params_.target - 1)) == 0;

    masked_ = powerOfTwo;
    if (powerOfTwo) {
        mask_ = params_.target - 1;
    }
}

void CdcSplitter::reset() {
    hash_ = 0;
    length_ = 0;
}

void CdcSplitter::nextChunk() {
    length_ = 0;
}

}
