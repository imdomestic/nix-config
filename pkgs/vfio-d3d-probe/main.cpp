#include <windows.h>
#include <d3d11.h>
#include <d3dcompiler.h>
#include <dxgi.h>
#include <cstdio>
#include <cstdlib>
#include <cstring>

// Offscreen draw + CPU readback: no interactive desktop or display window needed.
static void check(HRESULT hr, const char *stage) {
    if (FAILED(hr)) {
        std::fprintf(stderr, "%s failed: 0x%08lx\n", stage, (unsigned long)hr);
        std::exit(1);
    }
}
template<class T> struct Com {
    T *p = nullptr;
    ~Com() { if (p) p->Release(); }
    T *operator->() const { return p; }
    T **out() { return &p; }
};
int main(int argc, char **argv) {
    bool warp = argc == 2 && std::strcmp(argv[1], "--warp") == 0;
    if (argc > 1 && !warp) return 2;
    Com<ID3D11Device> device;
    Com<ID3D11DeviceContext> context;
    D3D_FEATURE_LEVEL obtained;
    D3D_FEATURE_LEVEL levels[] = {D3D_FEATURE_LEVEL_11_1, D3D_FEATURE_LEVEL_11_0};
    check(D3D11CreateDevice(nullptr, warp ? D3D_DRIVER_TYPE_WARP : D3D_DRIVER_TYPE_HARDWARE,
        nullptr, 0, levels, 2, D3D11_SDK_VERSION, device.out(), &obtained, context.out()), "CreateDevice");
    Com<IDXGIDevice> dxgi;
    Com<IDXGIAdapter> adapter;
    check(device->QueryInterface(__uuidof(IDXGIDevice), (void **)dxgi.out()), "QueryDXGI");
    check(dxgi->GetAdapter(adapter.out()), "GetAdapter");
    DXGI_ADAPTER_DESC desc{};
    check(adapter->GetDesc(&desc), "GetDesc");
    char name[512]{};
    WideCharToMultiByte(CP_UTF8, 0, desc.Description, -1, name, sizeof(name), nullptr, nullptr);
    std::printf("mode=%s adapter=%s vendor=0x%04x device=0x%04x featureLevel=0x%x\n",
        warp ? "WARP-selftest" : "hardware", name, desc.VendorId, desc.DeviceId, obtained);
    std::fflush(stdout);
    if (!warp && (desc.VendorId != 0x8086 || desc.DeviceId != 0x64a0)) {
        std::fprintf(stderr, "Expected Intel 8086:64a0; refusing software/other-adapter result\n");
        return 2;
    }
    const char *shader = R"(
float4 vs(uint id : SV_VertexID) : SV_Position {
    float2 p[3] = {float2(-1,-1), float2(-1,3), float2(3,-1)};
    return float4(p[id], 0, 1);
}
float4 ps() : SV_Target { return float4(0.25, 0.5, 0.75, 1); }
)";
    Com<ID3DBlob> vsCode, psCode;
    check(D3DCompile(shader, std::strlen(shader), nullptr, nullptr, nullptr, "vs", "vs_5_0", 0, 0, vsCode.out(), nullptr), "CompileVS");
    check(D3DCompile(shader, std::strlen(shader), nullptr, nullptr, nullptr, "ps", "ps_5_0", 0, 0, psCode.out(), nullptr), "CompilePS");
    Com<ID3D11VertexShader> vs;
    Com<ID3D11PixelShader> ps;
    check(device->CreateVertexShader(vsCode->GetBufferPointer(), vsCode->GetBufferSize(), nullptr, vs.out()), "CreateVS");
    check(device->CreatePixelShader(psCode->GetBufferPointer(), psCode->GetBufferSize(), nullptr, ps.out()), "CreatePS");
    constexpr UINT size = 256, frames = 120;
    D3D11_TEXTURE2D_DESC td{};
    td.Width = td.Height = size;
    td.MipLevels = td.ArraySize = td.SampleDesc.Count = 1;
    td.Format = DXGI_FORMAT_R8G8B8A8_UNORM;
    td.Usage = D3D11_USAGE_DEFAULT;
    td.BindFlags = D3D11_BIND_RENDER_TARGET;
    Com<ID3D11Texture2D> target, staging;
    check(device->CreateTexture2D(&td, nullptr, target.out()), "CreateTarget");
    td.Usage = D3D11_USAGE_STAGING;
    td.BindFlags = 0;
    td.CPUAccessFlags = D3D11_CPU_ACCESS_READ;
    check(device->CreateTexture2D(&td, nullptr, staging.out()), "CreateStaging");
    Com<ID3D11RenderTargetView> rtv;
    check(device->CreateRenderTargetView(target.p, nullptr, rtv.out()), "CreateRTV");
    D3D11_RASTERIZER_DESC rd{};
    rd.FillMode = D3D11_FILL_SOLID;
    rd.CullMode = D3D11_CULL_NONE;
    rd.DepthClipEnable = TRUE;
    Com<ID3D11RasterizerState> raster;
    check(device->CreateRasterizerState(&rd, raster.out()), "CreateRasterizer");
    context->RSSetState(raster.p);
    D3D11_VIEWPORT viewport{0, 0, float(size), float(size), 0, 1};
    context->RSSetViewports(1, &viewport);
    context->OMSetRenderTargets(1, &rtv.p, nullptr);
    context->IASetPrimitiveTopology(D3D11_PRIMITIVE_TOPOLOGY_TRIANGLELIST);
    context->VSSetShader(vs.p, nullptr, 0);
    context->PSSetShader(ps.p, nullptr, 0);
    const float black[4] = {0, 0, 0, 0};
    const int expected[4] = {64, 128, 191, 255};
    for (UINT frame = 0; frame < frames; ++frame) {
        context->ClearRenderTargetView(rtv.p, black);
        context->Draw(3, 0);
        context->CopyResource(staging.p, target.p);
        D3D11_MAPPED_SUBRESOURCE map{};
        check(context->Map(staging.p, 0, D3D11_MAP_READ, 0, &map), "Readback");
        bool valid = true;
        for (UINT y = 0; y < size && valid; ++y) {
            auto row = static_cast<const unsigned char *>(map.pData) + y * map.RowPitch;
            for (UINT x = 0; x < size && valid; ++x)
                for (UINT c = 0; c < 4; ++c)
                    if (std::abs(int(row[4*x+c]) - expected[c]) > 1) valid = false;
        }
        context->Unmap(staging.p, 0);
        if (!valid) { std::fprintf(stderr, "Pixel mismatch at frame %u\n", frame); return 3; }
    }
    check(device->GetDeviceRemovedReason(), "DeviceRemovedReason");
    std::printf("PASS: %u frames, %ux%u, every RGBA pixel verified; mode=%s\n",
        frames, size, size, warp ? "WARP-selftest" : "hardware");
    return 0;
}
