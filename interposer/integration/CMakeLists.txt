cmake_minimum_required(VERSION 3.28)

scion_add_cli11()

# =================
# interposer-target
# =================

add_executable(interposer-target
    "src/target.cpp"
)
target_link_libraries(interposer-target PRIVATE
    Boost::headers scion::cpp CLI11::CLI11
)

# ===================
# interposer-resolver
# ===================

add_executable(interposer-resolver
    "src/resolver.cpp"
)
target_link_libraries(interposer-resolver PRIVATE
    scion::cpp CLI11::CLI11
)
