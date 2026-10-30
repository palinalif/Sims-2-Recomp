#include "ts2/guest_image.hpp"
#include <fstream>
#include <iostream>
#include <stdexcept>

int main(int argc, char** argv) {
    try {
        if (argc != 2) throw std::invalid_argument("Expected one owner-authorized PE image path");
        std::ifstream input(argv[1],std::ios::binary | std::ios::ate);
        if (!input) throw std::runtime_error("Cannot open image");
        const auto size=input.tellg();
        if (size < 0 || size > 256*1024*1024) throw std::runtime_error("Image exceeds input budget");
        std::vector<uint8_t> bytes(static_cast<size_t>(size));
        input.seekg(0);
        if (!input.read(reinterpret_cast<char*>(bytes.data()),bytes.size()))
            throw std::runtime_error("Cannot read complete image");
        const auto image=ts2::load_guest_image(bytes);
        // Metadata only. No original bytes, names, paths or executable dispatch.
        std::cout << "image_size=" << image.image_size << " entry_rva=" << image.entry_rva
                  << " section_count=" << image.sections.size() << '\n';
        for (const auto& s : image.sections)
            std::cout << "section_rva=" << s.rva << " size=" << s.size
                      << " raw_size=" << s.raw_size << '\n';
    } catch (const std::exception& e) {
        std::cerr << "Guest image mapping rejected: " << e.what() << '\n'; return 1;
    }
}
