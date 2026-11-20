#include <stdio.h>
#include "../../virtio-d3d11-vpu-dev/vmedia_abi.h"

int main(void) {
    printf("commands=%08x,%08x,%08x,%08x,%08x\n",
        VM_IOCTL_ENC_CONFIG, VM_IOCTL_ENC_QUEUE_INPUT, VM_IOCTL_ENC_GET_PACKET,
        VM_IOCTL_ENC_DRAIN, VM_IOCTL_ENC_FLUSH);
    printf("sizes=%zu,%zu,%zu,%zu\n", sizeof(VM_ENCODER_CONFIG),
        sizeof(VM_ENCODER_INPUT), sizeof(VM_ENCODER_GET_PACKET_IN),
        sizeof(VM_ENCODER_PACKET_INFO));
    return 0;
}
