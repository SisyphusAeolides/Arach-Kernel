module arach_control
  use, intrinsic :: iso_c_binding, only: c_int32_t, c_int64_t
  implicit none
  private
  public :: arach_fortran_dot_q16

  integer(c_int32_t), parameter :: maximum_features = 64_c_int32_t
  integer(c_int32_t), parameter :: input_limit = 1048576_c_int32_t

contains

  function arach_fortran_dot_q16(features, weights, length, score) &
      bind(C, name="arach_fortran_dot_q16") result(status)
    integer(c_int32_t), intent(in) :: features(*)
    integer(c_int32_t), intent(in) :: weights(*)
    integer(c_int32_t), value, intent(in) :: length
    integer(c_int64_t), intent(out) :: score
    integer(c_int32_t) :: status
    integer(c_int32_t) :: index
    integer(c_int64_t) :: accumulator

    score = 0_c_int64_t
    if (length < 0_c_int32_t .or. length > maximum_features) then
      status = -1_c_int32_t
      return
    end if

    accumulator = 0_c_int64_t
    do index = 1_c_int32_t, length
      if (features(index) < -input_limit .or. features(index) > input_limit .or. &
          weights(index) < -input_limit .or. weights(index) > input_limit) then
        status = -2_c_int32_t
        return
      end if
      accumulator = accumulator + &
        int(features(index), c_int64_t) * int(weights(index), c_int64_t)
    end do

    score = accumulator
    status = 0_c_int32_t
  end function arach_fortran_dot_q16

end module arach_control
