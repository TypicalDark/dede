// SPDX-License-Identifier: Apache-2.0
//
// The Vulkan + GLFW host for the dede GUI. It owns the window, the Vulkan
// instance/device/swapchain and the Dear ImGui frame loop, and hands a
// dede::gui::Workspace exactly one dependency: an IAnalysisEngine. The Vulkan
// setup follows the vendored imgui example (examples/example_glfw_vulkan); only
// the per-frame UI body is ours. Requires a display; build with -DDEDE_WITH_GUI=ON.
#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_vulkan.h"
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <vector>
#define GLFW_INCLUDE_NONE
#define GLFW_INCLUDE_VULKAN
#include <GLFW/glfw3.h>

#include "dede/gui/workspace.hpp"
#include "dede/script/script_engine.hpp"
#include "dede/session/analysis_session.hpp"

using namespace dede;

// ---- Vulkan globals (as in the imgui example) -------------------------------
static VkAllocationCallbacks* g_Allocator = nullptr;
static VkInstance g_Instance = VK_NULL_HANDLE;
static VkPhysicalDevice g_PhysicalDevice = VK_NULL_HANDLE;
static VkDevice g_Device = VK_NULL_HANDLE;
static uint32_t g_QueueFamily = (uint32_t)-1;
static VkQueue g_Queue = VK_NULL_HANDLE;
static VkPipelineCache g_PipelineCache = VK_NULL_HANDLE;
static VkDescriptorPool g_DescriptorPool = VK_NULL_HANDLE;
static ImGui_ImplVulkanH_Window g_MainWindowData;
static uint32_t g_MinImageCount = 2;
static bool g_SwapChainRebuild = false;

static void check_vk(VkResult err) {
    if (err == 0) return;
    std::fprintf(stderr, "[vulkan] VkResult = %d\n", err);
    if (err < 0) std::abort();
}

static void SetupVulkan(std::vector<const char*> exts) {
    VkInstanceCreateInfo ci{};
    ci.sType = VK_STRUCTURE_TYPE_INSTANCE_CREATE_INFO;
    ci.enabledExtensionCount = (uint32_t)exts.size();
    ci.ppEnabledExtensionNames = exts.data();
    check_vk(vkCreateInstance(&ci, g_Allocator, &g_Instance));

    g_PhysicalDevice = ImGui_ImplVulkanH_SelectPhysicalDevice(g_Instance);
    g_QueueFamily = ImGui_ImplVulkanH_SelectQueueFamilyIndex(g_PhysicalDevice);

    const char* dev_ext[] = {"VK_KHR_swapchain"};
    const float prio[] = {1.0f};
    VkDeviceQueueCreateInfo q{};
    q.sType = VK_STRUCTURE_TYPE_DEVICE_QUEUE_CREATE_INFO;
    q.queueFamilyIndex = g_QueueFamily;
    q.queueCount = 1;
    q.pQueuePriorities = prio;
    VkDeviceCreateInfo dci{};
    dci.sType = VK_STRUCTURE_TYPE_DEVICE_CREATE_INFO;
    dci.queueCreateInfoCount = 1;
    dci.pQueueCreateInfos = &q;
    dci.enabledExtensionCount = 1;
    dci.ppEnabledExtensionNames = dev_ext;
    check_vk(vkCreateDevice(g_PhysicalDevice, &dci, g_Allocator, &g_Device));
    vkGetDeviceQueue(g_Device, g_QueueFamily, 0, &g_Queue);

    VkDescriptorPoolSize pool_sizes[] = {
        {VK_DESCRIPTOR_TYPE_SAMPLED_IMAGE, IMGUI_IMPL_VULKAN_MINIMUM_SAMPLED_IMAGE_POOL_SIZE},
        {VK_DESCRIPTOR_TYPE_SAMPLER, IMGUI_IMPL_VULKAN_MINIMUM_SAMPLER_POOL_SIZE}};
    VkDescriptorPoolCreateInfo pi{};
    pi.sType = VK_STRUCTURE_TYPE_DESCRIPTOR_POOL_CREATE_INFO;
    pi.flags = VK_DESCRIPTOR_POOL_CREATE_FREE_DESCRIPTOR_SET_BIT;
    for (auto& s : pool_sizes) pi.maxSets += s.descriptorCount;
    pi.poolSizeCount = (uint32_t)IM_ARRAYSIZE(pool_sizes);
    pi.pPoolSizes = pool_sizes;
    check_vk(vkCreateDescriptorPool(g_Device, &pi, g_Allocator, &g_DescriptorPool));
}

static void SetupVulkanWindow(ImGui_ImplVulkanH_Window* wd, VkSurfaceKHR surface, int w, int h) {
    wd->Surface = surface;
    VkBool32 res;
    vkGetPhysicalDeviceSurfaceSupportKHR(g_PhysicalDevice, g_QueueFamily, surface, &res);
    if (res != VK_TRUE) { std::fprintf(stderr, "no WSI support\n"); std::exit(1); }
    const VkFormat fmts[] = {VK_FORMAT_B8G8R8A8_UNORM, VK_FORMAT_R8G8B8A8_UNORM,
                             VK_FORMAT_B8G8R8_UNORM, VK_FORMAT_R8G8B8_UNORM};
    wd->SurfaceFormat = ImGui_ImplVulkanH_SelectSurfaceFormat(
        g_PhysicalDevice, wd->Surface, fmts, IM_ARRAYSIZE(fmts), VK_COLORSPACE_SRGB_NONLINEAR_KHR);
    VkPresentModeKHR modes[] = {VK_PRESENT_MODE_FIFO_KHR};
    wd->PresentMode = ImGui_ImplVulkanH_SelectPresentMode(g_PhysicalDevice, wd->Surface, modes, 1);
    ImGui_ImplVulkanH_CreateOrResizeWindow(g_Instance, g_PhysicalDevice, g_Device, wd, g_QueueFamily,
                                           g_Allocator, w, h, g_MinImageCount, 0);
}

static void FrameRender(ImGui_ImplVulkanH_Window* wd, ImDrawData* draw_data) {
    VkSemaphore img_sem = wd->FrameSemaphores[wd->SemaphoreIndex].ImageAcquiredSemaphore;
    VkSemaphore done_sem = wd->FrameSemaphores[wd->SemaphoreIndex].RenderCompleteSemaphore;
    VkResult err = vkAcquireNextImageKHR(g_Device, wd->Swapchain, UINT64_MAX, img_sem, VK_NULL_HANDLE, &wd->FrameIndex);
    if (err == VK_ERROR_OUT_OF_DATE_KHR || err == VK_SUBOPTIMAL_KHR) g_SwapChainRebuild = true;
    if (err == VK_ERROR_OUT_OF_DATE_KHR) return;
    ImGui_ImplVulkanH_Frame* fd = &wd->Frames[wd->FrameIndex];
    check_vk(vkWaitForFences(g_Device, 1, &fd->Fence, VK_TRUE, UINT64_MAX));
    check_vk(vkResetFences(g_Device, 1, &fd->Fence));
    check_vk(vkResetCommandPool(g_Device, fd->CommandPool, 0));
    VkCommandBufferBeginInfo bi{};
    bi.sType = VK_STRUCTURE_TYPE_COMMAND_BUFFER_BEGIN_INFO;
    bi.flags |= VK_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT;
    check_vk(vkBeginCommandBuffer(fd->CommandBuffer, &bi));
    VkRenderPassBeginInfo rp{};
    rp.sType = VK_STRUCTURE_TYPE_RENDER_PASS_BEGIN_INFO;
    rp.renderPass = wd->RenderPass;
    rp.framebuffer = fd->Framebuffer;
    rp.renderArea.extent.width = wd->Width;
    rp.renderArea.extent.height = wd->Height;
    rp.clearValueCount = 1;
    rp.pClearValues = &wd->ClearValue;
    vkCmdBeginRenderPass(fd->CommandBuffer, &rp, VK_SUBPASS_CONTENTS_INLINE);
    ImGui_ImplVulkan_RenderDrawData(draw_data, fd->CommandBuffer);
    vkCmdEndRenderPass(fd->CommandBuffer);
    VkPipelineStageFlags wait_stage = VK_PIPELINE_STAGE_COLOR_ATTACHMENT_OUTPUT_BIT;
    VkSubmitInfo si{};
    si.sType = VK_STRUCTURE_TYPE_SUBMIT_INFO;
    si.waitSemaphoreCount = 1;
    si.pWaitSemaphores = &img_sem;
    si.pWaitDstStageMask = &wait_stage;
    si.commandBufferCount = 1;
    si.pCommandBuffers = &fd->CommandBuffer;
    si.signalSemaphoreCount = 1;
    si.pSignalSemaphores = &done_sem;
    check_vk(vkEndCommandBuffer(fd->CommandBuffer));
    check_vk(vkQueueSubmit(g_Queue, 1, &si, fd->Fence));
}

static void FramePresent(ImGui_ImplVulkanH_Window* wd) {
    if (g_SwapChainRebuild) return;
    VkSemaphore done_sem = wd->FrameSemaphores[wd->SemaphoreIndex].RenderCompleteSemaphore;
    VkPresentInfoKHR info{};
    info.sType = VK_STRUCTURE_TYPE_PRESENT_INFO_KHR;
    info.waitSemaphoreCount = 1;
    info.pWaitSemaphores = &done_sem;
    info.swapchainCount = 1;
    info.pSwapchains = &wd->Swapchain;
    info.pImageIndices = &wd->FrameIndex;
    VkResult err = vkQueuePresentKHR(g_Queue, &info);
    if (err == VK_ERROR_OUT_OF_DATE_KHR || err == VK_SUBOPTIMAL_KHR) g_SwapChainRebuild = true;
    wd->SemaphoreIndex = (wd->SemaphoreIndex + 1) % wd->SemaphoreCount;
}

int main(int argc, char** argv) {
    // --- the analysis session the whole UI binds to -------------------------
    AnalysisSession session(Arch::X86_64);
    auto script = make_script_engine(session);
    session.map(0x1000, 0x10000, perm::RWX);
    session.map(0x70000, 0x10000, perm::RW);
    session.core().cpu().set(Reg::Rsp, 0x78000);
    if (argc >= 2) {
        std::ifstream f(argv[1], std::ios::binary);
        std::vector<u8> bytes{std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>()};
        if (!bytes.empty()) session.core().memory().write(0x1000, bytes);
    }
    session.set_entry(0x1000);

    // --- window + Vulkan ----------------------------------------------------
    if (!glfwInit()) { std::fprintf(stderr, "glfwInit failed (no display?)\n"); return 1; }
    glfwWindowHint(GLFW_CLIENT_API, GLFW_NO_API);
    GLFWwindow* window = glfwCreateWindow(1440, 900, "dede — time-travel analysis shell", nullptr, nullptr);
    if (!glfwVulkanSupported()) { std::fprintf(stderr, "Vulkan not supported\n"); return 1; }

    uint32_t ext_count = 0;
    const char** glfw_ext = glfwGetRequiredInstanceExtensions(&ext_count);
    SetupVulkan(std::vector<const char*>(glfw_ext, glfw_ext + ext_count));

    VkSurfaceKHR surface;
    check_vk(glfwCreateWindowSurface(g_Instance, window, g_Allocator, &surface));
    int w, h;
    glfwGetFramebufferSize(window, &w, &h);
    ImGui_ImplVulkanH_Window* wd = &g_MainWindowData;
    SetupVulkanWindow(wd, surface, w, h);

    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO();
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard | ImGuiConfigFlags_DockingEnable;
    ImGui::StyleColorsDark();

    ImGui_ImplGlfw_InitForVulkan(window, true);
    ImGui_ImplVulkan_InitInfo ii{};
    ii.Instance = g_Instance;
    ii.PhysicalDevice = g_PhysicalDevice;
    ii.Device = g_Device;
    ii.QueueFamily = g_QueueFamily;
    ii.Queue = g_Queue;
    ii.PipelineCache = g_PipelineCache;
    ii.DescriptorPool = g_DescriptorPool;
    ii.MinImageCount = g_MinImageCount;
    ii.ImageCount = wd->ImageCount;
    ii.Allocator = g_Allocator;
    ii.PipelineInfoMain.RenderPass = wd->RenderPass;
    ii.PipelineInfoMain.Subpass = 0;
    ii.PipelineInfoMain.MSAASamples = VK_SAMPLE_COUNT_1_BIT;
    ii.CheckVkResultFn = check_vk;
    ImGui_ImplVulkan_Init(&ii);

    gui::Workspace workspace(session, *script);
    workspace.attach();

    while (!glfwWindowShouldClose(window)) {
        glfwPollEvents();
        if (g_SwapChainRebuild) {
            glfwGetFramebufferSize(window, &w, &h);
            if (w > 0 && h > 0) {
                ImGui_ImplVulkan_SetMinImageCount(g_MinImageCount);
                ImGui_ImplVulkanH_CreateOrResizeWindow(g_Instance, g_PhysicalDevice, g_Device, wd,
                                                       g_QueueFamily, g_Allocator, w, h, g_MinImageCount, 0);
                wd->FrameIndex = 0;
                g_SwapChainRebuild = false;
            }
        }
        ImGui_ImplVulkan_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        workspace.draw();

        ImGui::Render();
        ImDrawData* dd = ImGui::GetDrawData();
        if (dd->DisplaySize.x > 0 && dd->DisplaySize.y > 0) {
            wd->ClearValue.color.float32[0] = 0.08f;
            wd->ClearValue.color.float32[1] = 0.09f;
            wd->ClearValue.color.float32[2] = 0.11f;
            wd->ClearValue.color.float32[3] = 1.0f;
            FrameRender(wd, dd);
            FramePresent(wd);
        }
    }

    workspace.detach();
    check_vk(vkDeviceWaitIdle(g_Device));
    ImGui_ImplVulkan_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    ImGui_ImplVulkanH_DestroyWindow(g_Instance, g_Device, wd, g_Allocator);
    vkDestroySurfaceKHR(g_Instance, wd->Surface, g_Allocator);
    vkDestroyDescriptorPool(g_Device, g_DescriptorPool, g_Allocator);
    vkDestroyDevice(g_Device, g_Allocator);
    vkDestroyInstance(g_Instance, g_Allocator);
    glfwDestroyWindow(window);
    glfwTerminate();
    return 0;
}
