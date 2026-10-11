// SPDX-FileCopyrightText: 2026 André Fiedler
// SPDX-License-Identifier: AGPL-3.0-or-later

import assert from 'node:assert/strict'
import { inflateSync } from 'node:zlib'

import { nativeImage } from 'electron'

import { shouldReplaceVisualScreenshot } from './visual-qa-contract.mjs'

const visualRasterScaleFactor = 2
const visualRasterColorSpace = Object.freeze({
    primaries: 'bt709',
    transfer: 'srgb',
    matrix: 'rgb',
    range: 'full'
})

/**
 * Computes the PNG Paeth filter predictor for one color channel.
 * @param {number} left - Reconstructed byte to the left.
 * @param {number} above - Reconstructed byte above.
 * @param {number} upperLeft - Reconstructed upper-left byte.
 * @returns {number} Nearest Paeth predictor byte.
 */
function paethPredictor(left, above, upperLeft) {
    const prediction = left + above - upperLeft
    const leftDistance = Math.abs(prediction - left)
    const aboveDistance = Math.abs(prediction - above)
    const upperLeftDistance = Math.abs(prediction - upperLeft)
    if (leftDistance <= aboveDistance && leftDistance <= upperLeftDistance) return left
    return aboveDistance <= upperLeftDistance ? above : upperLeft
}

/**
 * Decodes Electron's non-interlaced eight-bit RGB PNG representation into a
 * platform-independent top-down RGBA raster for structural-anchor checks.
 * @param {Buffer} png - Electron-generated PNG bytes.
 * @returns {{width: number, height: number, bitmap: Buffer}} Canonical RGBA raster.
 */
function decodeCanonicalPngRaster(png) {
    assert(png.subarray(0, 8).equals(Buffer.from([137, 80, 78, 71, 13, 10, 26, 10])), 'Visual anchor crop is not a PNG')
    let width = 0
    let height = 0
    const idatChunks = []
    for (let offset = 8; offset < png.length;) {
        const length = png.readUInt32BE(offset)
        const type = png.toString('ascii', offset + 4, offset + 8)
        const dataStart = offset + 8
        const dataEnd = dataStart + length
        assert(dataEnd + 4 <= png.length, 'Visual anchor PNG chunk is truncated')
        if (type === 'IHDR') {
            width = png.readUInt32BE(dataStart)
            height = png.readUInt32BE(dataStart + 4)
            assert.equal(png[dataStart + 8], 8, 'Visual anchor PNG must use eight-bit channels')
            assert.equal(png[dataStart + 9], 2, 'Visual anchor PNG must use RGB color')
            assert.equal(png[dataStart + 12], 0, 'Visual anchor PNG must not be interlaced')
        } else if (type === 'IDAT') {
            idatChunks.push(png.subarray(dataStart, dataEnd))
        }
        offset = dataEnd + 4
    }
    assert(Number.isSafeInteger(width) && width > 0 && Number.isSafeInteger(height) && height > 0 && idatChunks.length > 0, 'Visual anchor PNG metadata is incomplete')
    const bytesPerPixel = 3
    const stride = width * bytesPerPixel
    const filtered = inflateSync(Buffer.concat(idatChunks))
    assert.equal(filtered.length, (stride + 1) * height, 'Visual anchor PNG scanline size is invalid')
    const rgb = Buffer.alloc(stride * height)
    let sourceOffset = 0
    for (let y = 0; y < height; y += 1) {
        const filter = filtered[sourceOffset]
        sourceOffset += 1
        for (let x = 0; x < stride; x += 1) {
            const raw = filtered[sourceOffset + x]
            const outputIndex = y * stride + x
            const left = x >= bytesPerPixel ? rgb[outputIndex - bytesPerPixel] : 0
            const above = y > 0 ? rgb[outputIndex - stride] : 0
            const upperLeft = y > 0 && x >= bytesPerPixel ? rgb[outputIndex - stride - bytesPerPixel] : 0
            const predictor = filter === 0 ? 0 : filter === 1 ? left : filter === 2 ? above : filter === 3 ? Math.floor((left + above) / 2) : filter === 4 ? paethPredictor(left, above, upperLeft) : null
            assert.notEqual(predictor, null, `Visual anchor PNG uses unsupported filter ${filter}`)
            rgb[outputIndex] = (raw + predictor) & 0xff
        }
        sourceOffset += stride
    }
    const bitmap = Buffer.alloc(width * height * 4)
    for (let source = 0, target = 0; source < rgb.length; source += 3, target += 4) {
        bitmap[target] = rgb[source]
        bitmap[target + 1] = rgb[source + 1]
        bitmap[target + 2] = rgb[source + 2]
        bitmap[target + 3] = 255
    }
    return { width, height, bitmap }
}

/**
 * Round-trips Electron's platform-native sRGB bitmap through NativeImage so
 * the canonical PNG decoder sees sRGB bytes instead of display-profile bytes.
 * @param {Electron.NativeImage} image - Candidate screenshot representation.
 * @returns {Buffer} Canonical sRGB PNG bytes.
 */
function createCanonicalSrgbPng(image) {
    const normalizedImage = nativeImage.createFromBuffer(image.toPNG({ scaleFactor: visualRasterScaleFactor }))
    const { width, height } = normalizedImage.getSize(visualRasterScaleFactor)
    const bitmap = normalizedImage.toBitmap({
        scaleFactor: visualRasterScaleFactor,
        colorSpace: visualRasterColorSpace
    })
    return nativeImage.createFromBitmap(bitmap, { width, height, scaleFactor: visualRasterScaleFactor }).toPNG({ scaleFactor: visualRasterScaleFactor })
}

/**
 * Decodes one image at the explicit Retina scale and sRGB color space used by
 * tracked visual evidence.
 * @param {Electron.NativeImage} image - Screenshot representation to decode.
 * @returns {{width: number, height: number, bitmap: Buffer}} Physical raster.
 */
export function decodeVisualRaster(image) {
    const normalizedImage = nativeImage.createFromBuffer(
        image.toPNG({
            scaleFactor: visualRasterScaleFactor
        })
    )
    const { width, height } = normalizedImage.getSize(visualRasterScaleFactor)
    const bitmap = normalizedImage.toBitmap({
        scaleFactor: visualRasterScaleFactor,
        colorSpace: visualRasterColorSpace
    })
    assert.equal(bitmap.length, width * height * 4, 'Decoded visual raster dimensions do not match its bitmap')
    return { width, height, bitmap }
}

/**
 * Decodes the complete screenshot through canonical PNG orientation and then
 * extracts renderer-declared anchor rectangles, preventing pixels from
 * unrelated compositor layers from satisfying the anchor contract.
 * @param {Electron.NativeImage} image - Complete candidate screenshot.
 * @param {{name: string, color: string, rect: {left: number, top: number, right: number, bottom: number}}[]} anchors - CSS-pixel anchor rectangles.
 * @param {{width: number, height: number}} contentSize - Renderer content dimensions in CSS pixels.
 * @returns {{name: string, color: string, fiducialColor: string, raster: {width: number, height: number, bitmap: Buffer}}[]} Decoded canonical anchor crops.
 */
export function decodeVisualRasterAnchorCrops(image, anchors, contentSize) {
    const source = decodeCanonicalPngRaster(createCanonicalSrgbPng(image))
    assert(Number.isFinite(contentSize?.width) && contentSize.width > 0 && Number.isFinite(contentSize?.height) && contentSize.height > 0, 'Visual raster content size is invalid')
    const scaleX = source.width / contentSize.width
    const scaleY = source.height / contentSize.height
    return anchors.map((anchor) => {
        const x = Math.max(0, Math.floor(anchor.rect.left * scaleX))
        const y = Math.max(0, Math.floor(anchor.rect.top * scaleY))
        const right = Math.min(source.width, Math.ceil(anchor.rect.right * scaleX))
        const bottom = Math.min(source.height, Math.ceil(anchor.rect.bottom * scaleY))
        assert(right > x && bottom > y, `Visual raster anchor crop is empty: ${anchor.name}`)
        const width = right - x
        const height = bottom - y
        const bitmap = Buffer.alloc(width * height * 4)
        for (let row = 0; row < height; row += 1) {
            const sourceStart = ((y + row) * source.width + x) * 4
            source.bitmap.copy(bitmap, row * width * 4, sourceStart, sourceStart + width * 4)
        }
        return {
            name: anchor.name,
            color: anchor.color,
            fiducialColor: anchor.fiducialColor,
            raster: { width, height, bitmap }
        }
    })
}

/**
 * Compares two already normalized physical rasters with the production visual
 * evidence contract.
 * @param {{width: number, height: number, bitmap: Uint8Array}} trackedRaster - Canonical tracked raster.
 * @param {{width: number, height: number, bitmap: Uint8Array}} freshRaster - Fresh captured raster.
 * @returns {boolean} True only when the evidence contains meaningful drift.
 */
export function hasMeaningfulVisualDifference(trackedRaster, freshRaster) {
    return shouldReplaceVisualScreenshot(trackedRaster, freshRaster)
}

/**
 * Normalizes and compares two Electron images through the exact production
 * screenshot evidence boundary, including physical dimensions.
 * @param {Electron.NativeImage} trackedImage - Canonical tracked image.
 * @param {Electron.NativeImage} freshImage - Freshly captured image.
 * @returns {{trackedRaster: object, freshRaster: object, meaningfulDifference: boolean}} Comparison evidence.
 */
export function compareVisualImages(trackedImage, freshImage) {
    const trackedRaster = decodeVisualRaster(trackedImage)
    const freshRaster = decodeVisualRaster(freshImage)
    return {
        trackedRaster,
        freshRaster,
        meaningfulDifference: hasMeaningfulVisualDifference(trackedRaster, freshRaster)
    }
}

/**
 * Creates one-channel, one-level capture noise only after the caller proves the
 * real baseline already passed the strict evidence comparator.
 * @param {{width: number, height: number, bitmap: Buffer}} trackedRaster - Canonical tracked raster.
 * @param {{width: number, height: number, bitmap: Buffer}} freshRaster - Fresh captured raster.
 * @returns {{width: number, height: number, bitmap: Buffer}} Controlled noisy capture.
 */
export function injectSingleChannelRasterNoise(trackedRaster, freshRaster) {
    const bitmap = Buffer.from(trackedRaster.bitmap)
    bitmap[0] = trackedRaster.bitmap[0] === 255 ? 254 : trackedRaster.bitmap[0] + 1
    return { ...freshRaster, bitmap }
}
