/*
  ntfsclone2vhd -
  Converts ntfsclone "special image" to dynamic VHD virtual disk.

  Copyright (c) 2015, Jiri Hruska <jirka@fud.cz>

  Permission to use, copy, modify, and/or distribute this software for any
  purpose with or without fee is hereby granted, provided that the above
  copyright notice and this permission notice appear in all copies.

  THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
  WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
  MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
  ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
  WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
  ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR
  IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
*/

#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>

#ifdef _MSC_VER
  #include <io.h>
  #define open    _open
  #define close   _close
  #define read    _read
  #define write   _write
  #define lseek64 _lseeki64
  #define fstat64 _fstati64
  #define stat64  _stat64
  #define setmode _setmode
  typedef ptrdiff_t ssize_t;
  #define ntohs(_x)  htons(_x)
  #define htons(_x)  _byteswap_ushort(_x)
  #define htonl(_x)  _byteswap_ulong(_x)
  #define htonll(_x) _byteswap_uint64(_x)
#else
  #include <unistd.h>
  #include <netinet/in.h>
  #define O_BINARY     0
  #define O_SEQUENTIAL 0
  #if __BYTE_ORDER != __LITTLE_ENDIAN
    #error Update everything for big-endian architecture.
  #endif
  #define htonll(_x) __bswap_64(_x)
#endif

#define VERSION "1.0"
#define VERDATE "2015-03-10"

/*** ntfsclone ***/

#define NTFSCLONE_IMG_MAGIC "\0ntfsclone-image"
#define NTFSCLONE_IMG_MAGIC_SIZE 16

#define NTFSCLONE_IMG_VER_MAJOR 10
#define NTFSCLONE_IMG_VER_MINOR 1

/* All values are in little endian. */
#pragma pack(push, 1)
typedef struct ntfsclone_image_hdr {
  char magic[NTFSCLONE_IMG_MAGIC_SIZE];
  uint8_t major_ver;
  uint8_t minor_ver;
  uint32_t cluster_size;
  uint64_t device_size;
  uint64_t nr_clusters;
  uint64_t inuse;
  uint32_t offset_to_image_data;
} ntfsclone_image_hdr_t;
#pragma pack(pop)


/*** VHD ***/

/*
  Virtual Hard Disk Image Format Specification
  https://technet.microsoft.com/en-us/library/bb676673.aspx
*/

typedef struct vhd_disk_geometry {
  uint16_t            cylinders;
  uint8_t             heads;
  uint8_t             sectors_per_track;
} vhd_disk_geometry_t;

typedef struct vhd_footer {
  char                cookie[8];
  uint32_t            features;
  uint32_t            file_format_version;
  uint64_t            data_offset;
  uint32_t            timestamp;
  char                creator_application[4];
  uint32_t            creator_version;
  char                creator_host_os[4];
  uint64_t            original_size;
  uint64_t            current_size;
  vhd_disk_geometry_t disk_geometry;
  uint32_t            disk_type;
  uint32_t            checksum;
  uint8_t             unique_id[16];
  uint8_t             saved_state;
  uint8_t             reserved[427];
} vhd_footer_t;

typedef char vhd_footer_size_check[sizeof(vhd_footer_t) == 512 ? 1 : -1];

#define VHD_FOOTER_COOKIE       "conectix"

#define VHD_FEATURE_TEMPORARY   0x00000001
#define VHD_FEATURE_RESERVED    0x00000002

#define VHD_FILE_FORMAT_VERSION 0x00010000

/* January 1, 2000 12:00:00 AM in UTC/GMT */
#define VHD_TIMESTAMP_OFFSET    946684800

#define VHD_TYPE_NONE           0
#define VHD_TYPE_FIXED          2
#define VHD_TYPE_DYNAMIC        3
#define VHD_TYPE_DIFFERENCING   4

typedef struct vhd_parent_locator {
  uint32_t             code;
  uint32_t             data_space;
  uint32_t             data_length;
  uint32_t             reserved;
  uint64_t             data_offset;
} vhd_parent_locator_t;

typedef struct vhd_dynamic_header {
  char                 cookie[8];
  uint64_t             data_offset;
  uint64_t             table_offset;
  uint32_t             header_version;
  uint32_t             max_table_entries;
  uint32_t             block_size;
  uint32_t             checksum;
  uint8_t              parent_unique_id[16];
  uint32_t             parent_timestamp;
  uint32_t             reserved0;
  uint16_t             parent_unicode_name[256];
  vhd_parent_locator_t parent_locator[8];
  uint8_t              reserved[256];
} vhd_dynamic_header_t;

typedef char vhd_dynamic_header_size_check[sizeof(vhd_dynamic_header_t) == 1024 ? 1 : -1];

#define VHD_DYNAMIC_HEADER_COOKIE  "cxsparse"

#define VHD_DYNAMIC_HEADER_VERSION 0x00010000

#define VHD_DYNAMIC_BLOCK_SIZE     (2 * 1048576)


static uint32_t vhd_calc_checksum(const void* data, size_t size)
{
  uint32_t sum = 0;
  for (unsigned i = 0; i < size; i++)
    sum += ((uint8_t*)data)[i];
  return ~sum;
}

/* Per "Appendix: CHS Calculation" from VHD specification */
static void vhd_calc_disk_geometry(uint64_t total_size, vhd_disk_geometry_t* dg)
{
  unsigned total_sectors;
  if (total_size > 65535 * 16 * 255 * 512ull)
    total_sectors = 65535 * 16 * 255;
  else
    total_sectors = (unsigned)(total_size / 512);

  unsigned cylinder_times_heads;
  if (total_sectors >= 65535 * 16 * 63) {
    dg->sectors_per_track = 255;
    dg->heads = 16;
    cylinder_times_heads = total_sectors / dg->sectors_per_track;
  } else {
    dg->sectors_per_track = 17;
    cylinder_times_heads = total_sectors / dg->sectors_per_track;

    dg->heads = (cylinder_times_heads + 1023) / 1024;
    if (dg->heads < 4)
      dg->heads = 4;

    if (cylinder_times_heads >= dg->heads * 1024u || dg->heads > 16) {
      dg->sectors_per_track = 31;
      dg->heads = 16;
      cylinder_times_heads = total_sectors / dg->sectors_per_track;
    }
    if (cylinder_times_heads >= dg->heads * 1024u) {
      dg->sectors_per_track = 63;
      dg->heads = 16;
      cylinder_times_heads = total_sectors / dg->sectors_per_track;
    }
  }
  dg->cylinders = htons(cylinder_times_heads / dg->heads);
}



/*** MBR ***/

#pragma pack(push, 1)

typedef struct mbr_entry {
  uint8_t  active;
  uint8_t  first_chs[3];
  uint8_t  system_id;
  uint8_t  last_chs[3];
  uint32_t first_lba;
  uint32_t lba_count;
} mbr_entry_t;

typedef struct mbr {
  uint8_t     bootstrap[0x1B8];
  uint32_t    signature;
  uint16_t    null;
  mbr_entry_t partition[4];
  uint8_t     magic[2];
} mbr_t;

#pragma pack(pop)

typedef char mbr_size_check[sizeof(mbr_t) == 512 ? 1 : -1];


/* Working MBR stolen from a working disk. Probably (c) Microsoft */
static const uint8_t mbr_template[512] = {
  0x33, 0xC0, 0x8E, 0xD0, 0xBC, 0x00, 0x7C, 0x8E, 0xC0, 0x8E, 0xD8, 0xBE, 0x00, 0x7C, 0xBF, 0x00,
  0x06, 0xB9, 0x00, 0x02, 0xFC, 0xF3, 0xA4, 0x50, 0x68, 0x1C, 0x06, 0xCB, 0xFB, 0xB9, 0x04, 0x00,
  0xBD, 0xBE, 0x07, 0x80, 0x7E, 0x00, 0x00, 0x7C, 0x0B, 0x0F, 0x85, 0x0E, 0x01, 0x83, 0xC5, 0x10,
  0xE2, 0xF1, 0xCD, 0x18, 0x88, 0x56, 0x00, 0x55, 0xC6, 0x46, 0x11, 0x05, 0xC6, 0x46, 0x10, 0x00,
  0xB4, 0x41, 0xBB, 0xAA, 0x55, 0xCD, 0x13, 0x5D, 0x72, 0x0F, 0x81, 0xFB, 0x55, 0xAA, 0x75, 0x09,
  0xF7, 0xC1, 0x01, 0x00, 0x74, 0x03, 0xFE, 0x46, 0x10, 0x66, 0x60, 0x80, 0x7E, 0x10, 0x00, 0x74,
  0x26, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0xFF, 0x76, 0x08, 0x68, 0x00, 0x00, 0x68, 0x00,
  0x7C, 0x68, 0x01, 0x00, 0x68, 0x10, 0x00, 0xB4, 0x42, 0x8A, 0x56, 0x00, 0x8B, 0xF4, 0xCD, 0x13,
  0x9F, 0x83, 0xC4, 0x10, 0x9E, 0xEB, 0x14, 0xB8, 0x01, 0x02, 0xBB, 0x00, 0x7C, 0x8A, 0x56, 0x00,
  0x8A, 0x76, 0x01, 0x8A, 0x4E, 0x02, 0x8A, 0x6E, 0x03, 0xCD, 0x13, 0x66, 0x61, 0x73, 0x1C, 0xFE,
  0x4E, 0x11, 0x75, 0x0C, 0x80, 0x7E, 0x00, 0x80, 0x0F, 0x84, 0x8A, 0x00, 0xB2, 0x80, 0xEB, 0x84,
  0x55, 0x32, 0xE4, 0x8A, 0x56, 0x00, 0xCD, 0x13, 0x5D, 0xEB, 0x9E, 0x81, 0x3E, 0xFE, 0x7D, 0x55,
  0xAA, 0x75, 0x6E, 0xFF, 0x76, 0x00, 0xE8, 0x8D, 0x00, 0x75, 0x17, 0xFA, 0xB0, 0xD1, 0xE6, 0x64,
  0xE8, 0x83, 0x00, 0xB0, 0xDF, 0xE6, 0x60, 0xE8, 0x7C, 0x00, 0xB0, 0xFF, 0xE6, 0x64, 0xE8, 0x75,
  0x00, 0xFB, 0xB8, 0x00, 0xBB, 0xCD, 0x1A, 0x66, 0x23, 0xC0, 0x75, 0x3B, 0x66, 0x81, 0xFB, 0x54,
  0x43, 0x50, 0x41, 0x75, 0x32, 0x81, 0xF9, 0x02, 0x01, 0x72, 0x2C, 0x66, 0x68, 0x07, 0xBB, 0x00,
  0x00, 0x66, 0x68, 0x00, 0x02, 0x00, 0x00, 0x66, 0x68, 0x08, 0x00, 0x00, 0x00, 0x66, 0x53, 0x66,
  0x53, 0x66, 0x55, 0x66, 0x68, 0x00, 0x00, 0x00, 0x00, 0x66, 0x68, 0x00, 0x7C, 0x00, 0x00, 0x66,
  0x61, 0x68, 0x00, 0x00, 0x07, 0xCD, 0x1A, 0x5A, 0x32, 0xF6, 0xEA, 0x00, 0x7C, 0x00, 0x00, 0xCD,
  0x18, 0xA0, 0xB7, 0x07, 0xEB, 0x08, 0xA0, 0xB6, 0x07, 0xEB, 0x03, 0xA0, 0xB5, 0x07, 0x32, 0xE4,
  0x05, 0x00, 0x07, 0x8B, 0xF0, 0xAC, 0x3C, 0x00, 0x74, 0x09, 0xBB, 0x07, 0x00, 0xB4, 0x0E, 0xCD,
  0x10, 0xEB, 0xF2, 0xF4, 0xEB, 0xFD, 0x2B, 0xC9, 0xE4, 0x64, 0xEB, 0x00, 0x24, 0x02, 0xE0, 0xF8,
  0x24, 0x02, 0xC3, 0x49, 0x6E, 0x76, 0x61, 0x6C, 0x69, 0x64, 0x20, 0x70, 0x61, 0x72, 0x74, 0x69,
  0x74, 0x69, 0x6F, 0x6E, 0x20, 0x74, 0x61, 0x62, 0x6C, 0x65, 0x00, 0x45, 0x72, 0x72, 0x6F, 0x72,
  0x20, 0x6C, 0x6F, 0x61, 0x64, 0x69, 0x6E, 0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69,
  0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74, 0x65, 0x6D, 0x00, 0x4D, 0x69, 0x73, 0x73, 0x69, 0x6E,
  0x67, 0x20, 0x6F, 0x70, 0x65, 0x72, 0x61, 0x74, 0x69, 0x6E, 0x67, 0x20, 0x73, 0x79, 0x73, 0x74,
  0x65, 0x6D, 0x00, 0x00, 0x00, 0x63, 0x7B, 0x9A, 0xE3, 0xF5, 0x4C, 0xCF, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x55, 0xAA
};


static void mbr_calc_chs_single(uint8_t* chs, uint32_t lba, unsigned cylinders, unsigned heads, unsigned sectors_per_track)
{
  unsigned c = lba / (cylinders * heads);
  unsigned h = (lba / sectors_per_track) % heads;
  unsigned s = (lba % sectors_per_track) + 1;
  chs[0] = (uint8_t)h;
  chs[1] = (uint8_t)(((c >> 2) & 0xC0) | s);
  chs[2] = (uint8_t)c;
}

static void mbr_calc_chs(mbr_entry_t* entry, unsigned cylinders, unsigned heads, unsigned sectors_per_track)
{
  mbr_calc_chs_single(entry->first_chs, entry->first_lba,                        cylinders, heads, sectors_per_track);
  mbr_calc_chs_single(entry->last_chs,  entry->first_lba + entry->lba_count - 1, cylinders, heads, sectors_per_track);
}


/***/


/* Handle possible split read when reading from pipe (stdin) */
int read_full(int fd, void* dst, unsigned num)
{
  char* ptr = (char*)dst;
  while (num > 0) {
    int result = read(fd, ptr, num);
    if (result < 0)
      return -1;
    if (result == 0)
      break;
    ptr += result;
    num -= result;
  }
  return (int)(ptr - (char*)dst);
}


int main(int argc, char** argv)
{
  fprintf(stderr,
    "-= ntfsclone2vhd " VERSION " - <jirka@fud.cz> " VERDATE " =-\n"
    "Converts ntfsclone \"special image\" to dynamic VHD virtual disk.\n"
    "\n");

  if (argc < 3) {
    fprintf(stderr,
      "Usage:\n"
      "\n"
      "    ntfsclone2vhd <input.ntfsclone> <output.vhd>\n"
      "        - Converts input.ntfsclone to output.vhd\n"
      "\n"
      "    ntfsclone2vhd - <output.vhd>\n"
      "        - Converts standard input to output.vhd,\n"
      "          can be piped from `ntfsclone -s` directly\n"
      "\n");
    return -1;
  }


  srand((unsigned)time(NULL));

  int ifd         = -1;
  int ofd         = -1;
  uint32_t* bat   = NULL;
  uint8_t*  block = NULL;


  if (strcmp(argv[1], "-") == 0) {
    ifd = 0;
    setmode(ifd, O_BINARY);
  } else {
    ifd = open(argv[1], O_RDONLY | O_BINARY | O_SEQUENTIAL);
    if (ifd < 0) {
      perror("Could not open source file");
      goto error;
    }
  }

  struct stat64 istat;
  if (fstat64(ifd, &istat) < 0) {
    fprintf(stderr, "Could not stat input, using current timestamp.\n");
    istat.st_mtime = time(NULL);
  }

  ntfsclone_image_hdr_t ihdr;
  if (read_full(ifd, &ihdr, sizeof(ihdr)) != sizeof(ihdr)) {
    perror("Could not read source header");
    goto error;
  }

  if (memcmp(ihdr.magic, NTFSCLONE_IMG_MAGIC, NTFSCLONE_IMG_MAGIC_SIZE) != 0 ||
      ihdr.major_ver != NTFSCLONE_IMG_VER_MAJOR)
  {
    fprintf(stderr, "Source file does not have a valid ntfsclone header.");
    goto error;
  }
  fprintf(stderr,
    "Input has a valid ntfsclone header:\n"
    "    Device size:    %10llu B (%u MB)\n"
    "    Cluster size:   %10u B\n"
    "    Total clusters: %10llu\n"
    "    Used clusters:  %10llu\n"
    "    Image data ofs: 0x%08X\n"
    "\n",
    ihdr.device_size, (unsigned)(ihdr.device_size / 1048576),
    ihdr.cluster_size, ihdr.nr_clusters, ihdr.inuse, ihdr.offset_to_image_data);

  if (ihdr.cluster_size < 512 ||
      ihdr.cluster_size % 512 != 0 ||
      VHD_DYNAMIC_BLOCK_SIZE % ihdr.cluster_size != 0)
  {
    fprintf(stderr, "Incompatible source cluster size.\n");
    goto error;
  }
  uint64_t new_device_size     = ihdr.cluster_size /*MBR*/ + ihdr.device_size;
  unsigned sectors_per_block   = VHD_DYNAMIC_BLOCK_SIZE / 512;
  unsigned sectors_per_cluster = ihdr.cluster_size / 512;
  unsigned num_blocks          = (unsigned)((new_device_size + VHD_DYNAMIC_BLOCK_SIZE - 1) / VHD_DYNAMIC_BLOCK_SIZE);

  if (ihdr.offset_to_image_data != sizeof(ihdr)) {
    /* Try a small read first, works on stdin too. The offset is just 6 bytes usually anyway. */
    char buf[8];
    unsigned amount = ihdr.offset_to_image_data - sizeof(ihdr);
    if (amount > sizeof(buf) || read_full(ifd, buf, amount) != amount) {
      if (lseek64(ifd, ihdr.offset_to_image_data, SEEK_SET) != ihdr.offset_to_image_data) {
        perror("Could not seek to source data");
        goto error;
      }
    }
  }


  ofd = open(argv[2], O_CREAT | O_TRUNC | O_WRONLY | O_BINARY | O_SEQUENTIAL, 0660);
  if (ofd < 0) {
    perror("Could not open destination file");
    goto error;
  }

  vhd_footer_t oftr;
  memset(&oftr, 0, sizeof(oftr));
  strncpy(oftr.cookie, VHD_FOOTER_COOKIE, sizeof(oftr.cookie));
  oftr.features = htonl(VHD_FEATURE_RESERVED);
  oftr.file_format_version = htonl(VHD_FILE_FORMAT_VERSION);
  oftr.data_offset = htonll(512);
  oftr.timestamp = htonl((uint32_t)istat.st_mtime - VHD_TIMESTAMP_OFFSET);
  strncpy(oftr.creator_application, "nc2v", sizeof(oftr.creator_application));
  oftr.creator_version = htonl(0x00010000);
  strncpy(oftr.creator_host_os, "Wi2k", sizeof(oftr.creator_host_os));
  oftr.original_size = htonll(new_device_size);
  oftr.current_size = htonll(new_device_size);
  vhd_calc_disk_geometry(new_device_size, &oftr.disk_geometry);
  oftr.disk_type = htonl(VHD_TYPE_DYNAMIC);
  for (int i = 0; i < sizeof(oftr.unique_id) / 2; i++)
    ((uint16_t*)oftr.unique_id)[i] ^= rand();
  oftr.saved_state = 0;
  oftr.checksum = htonl(vhd_calc_checksum(&oftr, sizeof(oftr)));

  if (write(ofd, &oftr, sizeof(oftr)) != sizeof(oftr)) {
    perror("Could not write VHD \"footer\" header");
    goto error;
  }


  vhd_dynamic_header_t ohdr;
  memset(&ohdr, 0, sizeof(ohdr));
  strncpy(ohdr.cookie, VHD_DYNAMIC_HEADER_COOKIE, sizeof(ohdr.cookie));
  ohdr.data_offset = htonll(~0ull);
  ohdr.table_offset = htonll(512 + 1024);
  ohdr.header_version = htonl(VHD_DYNAMIC_HEADER_VERSION);
  ohdr.max_table_entries = htonl(num_blocks);
  ohdr.block_size = htonl(VHD_DYNAMIC_BLOCK_SIZE);
  ohdr.checksum = htonl(vhd_calc_checksum(&ohdr, sizeof(ohdr)));

  if (write(ofd, &ohdr, sizeof(ohdr)) != sizeof(ohdr)) {
    perror("Could not write VHD dynamic header");
    goto error;
  }


  unsigned bat_buf_size = (num_blocks * 4 + 511) & ~511;
  bat = (uint32_t*)malloc(bat_buf_size);
  if (!bat) {
    perror("Could not allocate BAT");
    goto error;
  }
  memset(bat, 0xFF, bat_buf_size);

  if (write(ofd, bat, bat_buf_size) != bat_buf_size) {
    perror("Could not write empty BAT");
    goto error;
  }


  unsigned block_buf_size = 512 + VHD_DYNAMIC_BLOCK_SIZE;
  block = (uint8_t*)malloc(block_buf_size);
  if (!block) {
    perror("Could not allocate block buffer");
    goto error;
  }


  fprintf(stderr, "Converting data:\n");

  uint64_t clusters_read = 0;
  uint64_t sectors_to_skip = 0;
  unsigned block_no = 0;

  while (clusters_read < ihdr.nr_clusters) {
    if (sectors_to_skip >= sectors_per_block) {
      block_no++;
      sectors_to_skip -= sectors_per_block;
      continue;
    }

    unsigned ofs = (unsigned)sectors_to_skip;
    sectors_to_skip = 0;
    memset(block, 0x00, block_buf_size);
    int dirty = 0;

    if (clusters_read == 0) {
      mbr_t* mbr = (mbr_t*)(block + 512);
      memcpy(mbr, mbr_template, 512);
      mbr->signature = *(uint32_t*)oftr.unique_id;
      mbr->partition[0].active    = 0x80;
      mbr->partition[0].system_id = 0x07; /*NTFS*/
      mbr->partition[0].first_lba = sectors_per_cluster;
      mbr->partition[0].lba_count = (uint32_t)((ihdr.device_size + 511) / 512);
      mbr_calc_chs(&mbr->partition[0], ntohs(oftr.disk_geometry.cylinders), oftr.disk_geometry.heads, oftr.disk_geometry.sectors_per_track);
      block[0] = 0x80;
      dirty = 1;
      ofs = sectors_per_cluster;
    }

    while (clusters_read < ihdr.nr_clusters) {
      if (clusters_read % 64 == 0)
        fprintf(stderr, "    %3d%%...\r", (int)(100 * clusters_read / ihdr.nr_clusters));

      char cmd;
      if (read_full(ifd, &cmd, sizeof(cmd)) != sizeof(cmd)) {
        perror("Could not read source data");
        goto error;
      }

      if (cmd == 0) {
        uint64_t count;
        if (read_full(ifd, &count, sizeof(count)) != sizeof(count)) {
          perror("Could not read source data");
          goto error;
        }
        if (count > ihdr.nr_clusters - clusters_read) {
          fprintf(stderr, "Invalid empty cluster run in source file.\n");
          goto error;
        }
        clusters_read += count;

        if (count * sectors_per_cluster < sectors_per_block - ofs) {
          ofs += (unsigned)count * sectors_per_cluster;
        } else {
          sectors_to_skip = count * sectors_per_cluster - (sectors_per_block - ofs);
          break;
        }
      } else if (cmd == 1) {
        dirty = 1;
        if (read_full(ifd, block + 512 + (ofs * 512), ihdr.cluster_size) != ihdr.cluster_size) {
          perror("Could not read source data");
          goto error;
        }
        for (unsigned i = 0; i < sectors_per_cluster; i++) {
          block[ofs / 8] |= 0x80 >> (ofs % 8);
          ofs++;
        }
        clusters_read++;
        if (ofs >= sectors_per_block)
          break;
      } else {
        fprintf(stderr, "Lost sync in source file.\n");
        goto error;
      }
    }

    if (dirty) {
      bat[block_no] = htonl((uint32_t)(lseek64(ofd, 0, SEEK_CUR) / 512));
      if (write(ofd, block, block_buf_size) != block_buf_size) {
        perror("Could not write destination data");
        goto error;
      }
    }
    block_no++;
  }


  free(block);

  if (write(ofd, &oftr, sizeof(oftr)) != sizeof(oftr)) {
    perror("Could not write VHD footer");
    goto error;
  }

  if (lseek64(ofd, 512 + 1024, SEEK_SET) != 512 + 1024) {
    perror("Could not seek to BAT");
    goto error;
  }
  if (write(ofd, bat, bat_buf_size) != bat_buf_size) {
    perror("Could not write updated BAT");
    goto error;
  }
  free(bat);

  if (close(ofd) < 0) {
    perror("Could not close destination file");
    goto error;
  }

  if (ifd > 0)
    close(ifd);

  fprintf(stderr, "    100%% done.\n");
  return 0;


error:
  free(block);
  free(bat);
  if (ofd >= 0)
    close(ofd);
  if (ifd > 0)
    close(ifd);
  return -1;
}
