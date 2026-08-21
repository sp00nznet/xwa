/*
 * HLSL Shader Source for D3D11 Rendering Backend
 *
 * These are compiled at runtime via D3DCompile().
 * Two shader pairs:
 *   - vs_tlvertex + ps_textured: For textured geometry
 *   - vs_tlvertex + ps_solid: For untextured (vertex color only) geometry
 */

#ifndef SHADERS_H
#define SHADERS_H

static const char g_shader_source[] =
    "cbuffer ViewportCB : register(b0) {\n"
    "    float viewport_width;\n"
    "    float viewport_height;\n"
    "    float tex_blend;   // D3DRENDERSTATE_TEXTUREMAPBLEND (D3DTBLEND_*)\n"
    "    float padding;\n"
    "};\n"
    "\n"
    "struct VS_INPUT {\n"
    "    float4 pos_rhw : POSITION;  // sx, sy, sz, rhw\n"
    "    float4 diffuse : COLOR0;\n"
    "    float4 specular : COLOR1;\n"
    "    float2 tex : TEXCOORD0;\n"
    "};\n"
    "\n"
    "struct VS_OUTPUT {\n"
    "    float4 pos : SV_POSITION;\n"
    "    float4 diffuse : COLOR0;\n"
    "    float4 specular : COLOR1;\n"
    "    float2 tex : TEXCOORD0;\n"
    "};\n"
    "\n"
    "VS_OUTPUT vs_tlvertex(VS_INPUT input) {\n"
    "    VS_OUTPUT output;\n"
    "    // Transform screen coords (0-W, 0-H) to NDC (-1 to +1)\n"
    "    output.pos.x = (input.pos_rhw.x / viewport_width) * 2.0 - 1.0;\n"
    "    output.pos.y = 1.0 - (input.pos_rhw.y / viewport_height) * 2.0;\n"
    "    output.pos.z = input.pos_rhw.z;\n"
    "    output.pos.w = 1.0;\n"
    "    output.diffuse = input.diffuse;\n"
    "    output.specular = input.specular;\n"
    "    output.tex = input.tex;\n"
    "    return output;\n"
    "}\n"
    "\n"
    "Texture2D tex0 : register(t0);\n"
    "SamplerState samp0 : register(s0);\n"
    "\n"
    "float4 ps_textured(VS_OUTPUT input) : SV_TARGET {\n"
    "    float4 texel = tex0.Sample(samp0, input.tex);\n"
    "    // D3DTBLEND: 1=DECAL 2=MODULATE 3=DECALALPHA 4=MODULATEALPHA 6=COPY 7=ADD.\n"
    "    // DECAL/COPY mean the TEXTURE REPLACES the vertex colour -- unconditionally\n"
    "    // modulating turned every textured pixel black when diffuse was 0xFF000000.\n"
    "    if (tex_blend < 1.5 || tex_blend > 5.5) return texel;          // DECAL, COPY\n"
    "    if (tex_blend > 6.5) return saturate(texel + input.diffuse);   // ADD\n"
    "    if (tex_blend > 3.5) return texel * input.diffuse;             // MODULATEALPHA\n"
    "    return float4(texel.rgb * input.diffuse.rgb, input.diffuse.a); // MODULATE\n"
    "}\n"
    "\n"
    "float4 ps_solid(VS_OUTPUT input) : SV_TARGET {\n"
    "    return input.diffuse;\n"
    "}\n";

#endif /* SHADERS_H */
